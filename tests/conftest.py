"""
Pytest configuration and fixtures for Dshell testing.

This module provides reusable fixtures for testing the Dshell network analysis framework,
including mock objects for packets, connections, blobs, and external dependencies.
"""

import datetime
import struct
from collections import defaultdict
from multiprocessing import Value
from unittest.mock import MagicMock, Mock, patch

import pytest

from pypacker.layer12 import ethernet
from pypacker.layer3 import ip, ip6
from pypacker.layer4 import tcp, udp


def create_real_pypacker_packet(
    src_ip="192.168.1.1",
    dst_ip="192.168.1.2",
    src_port=12345,
    dst_port=80,
    protocol=6,
    data=b"test data",
    tcp_flags=0x18,
    seq=1000,
    ack=2000,
    src_mac="00:11:22:33:44:55",
    dst_mac="66:77:88:99:aa:bb",
    is_fragment=False,
    fragment_offset=0,
    fragment_id=0,
    more_fragments=False,
):
    """Create a real pypacker packet for testing."""
    src_mac_bytes = bytes.fromhex(src_mac.replace(":", ""))
    dst_mac_bytes = bytes.fromhex(dst_mac.replace(":", ""))

    if protocol == 6:
        transport_layer = tcp.TCP(sport=src_port, dport=dst_port, seq=seq, ack=ack, flags=tcp_flags, body_bytes=data)
    elif protocol == 17:
        transport_layer = udp.UDP(sport=src_port, dport=dst_port, body_bytes=data)
    else:
        transport_layer = None

    ip_flags = 0
    if more_fragments:
        ip_flags |= 0x1

    ip_layer = ip.IP(
        src_s=src_ip,
        dst_s=dst_ip,
        p=protocol,
        flags=ip_flags,
        offset=fragment_offset,
        id=fragment_id,
    )
    if transport_layer:
        ip_layer.upper_layer = transport_layer

    eth_layer = ethernet.Ethernet(
        src=src_mac_bytes,
        dst=dst_mac_bytes,
        type=ethernet.ETH_TYPE_IP,
    )
    eth_layer.upper_layer = ip_layer

    return eth_layer


class MockPypackerPacket:
    """Mock pypacker packet object for testing without actual packet parsing."""

    def __init__(
        self,
        src_ip="192.168.1.1",
        dst_ip="192.168.1.2",
        src_port=12345,
        dst_port=80,
        protocol=6,
        data=b"test data",
        tcp_flags=0x18,
        seq=1000,
        ack=2000,
        src_mac="00:11:22:33:44:55",
        dst_mac="66:77:88:99:aa:bb",
        is_fragment=False,
        fragment_offset=0,
        fragment_id=0,
        more_fragments=False,
    ):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self._data = data
        self.tcp_flags = tcp_flags
        self.seq = seq
        self.ack = ack
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.is_fragment = is_fragment
        self.fragment_offset = fragment_offset
        self.fragment_id = fragment_id
        self.more_fragments = more_fragments

        self._real_packet = create_real_pypacker_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            data=data,
            tcp_flags=tcp_flags,
            seq=seq,
            ack=ack,
            src_mac=src_mac,
            dst_mac=dst_mac,
            is_fragment=is_fragment,
            fragment_offset=fragment_offset,
            fragment_id=fragment_id,
            more_fragments=more_fragments,
        )

    def __iter__(self):
        """Iterate through packet layers."""
        return iter(self._real_packet)

    def __len__(self):
        return len(self._real_packet.bin())

    def bin(self):
        """Return raw packet bytes."""
        return self._real_packet.bin()

    @property
    def highest_layer(self):
        highest = None
        for layer in self._real_packet:
            highest = layer
        return highest

    @property
    def upper_layer(self):
        """Return the upper layer (IP layer) of the packet."""
        return self._real_packet.upper_layer


class MockEthernetLayer:
    """Mock Ethernet layer."""

    def __init__(self, src_mac, dst_mac):
        self.src_s = src_mac
        self.dst_s = dst_mac


class MockIPLayer:
    """Mock IP layer."""

    def __init__(
        self, src_ip, dst_ip, protocol, is_fragment=False, offset=0, id_=0, mf=False
    ):
        self.src_s = src_ip
        self.dst_s = dst_ip
        self.src = self._ip_to_bytes(src_ip)
        self.dst = self._ip_to_bytes(dst_ip)
        self.p = protocol
        self.offset = offset
        self.id = id_
        self.flags = 0x1 if mf else 0x0
        self.len = 100
        self.header_len = 20
        self.body_bytes = b""
        self.header_bytes = b"\x45\x00\x00\x64" + b"\x00" * 16

    def _ip_to_bytes(self, ip_str):
        """Convert IP string to bytes."""
        try:
            parts = [int(p) for p in ip_str.split(".")]
            return bytes(parts)
        except (ValueError, AttributeError):
            return b"\x00\x00\x00\x00"


class MockTCPLayer:
    """Mock TCP layer."""

    def __init__(self, sport, dport, flags, seq, ack, data):
        self.sport = sport
        self.dport = dport
        self.flags = flags
        self.seq = seq
        self.ack = ack
        self.body_bytes = data
        self.header_len = 20


class MockUDPLayer:
    """Mock UDP layer."""

    def __init__(self, sport, dport, data):
        self.sport = sport
        self.dport = dport
        self.body_bytes = data


class MockPcapyCapture:
    """Mock pcapy capture object."""

    def __init__(self, packets=None, datalink=1):
        self.packets = packets or []
        self._index = 0
        self._datalink = datalink

    def next(self):
        """Return next packet."""
        if self._index >= len(self.packets):
            return None, None
        header, data = self.packets[self._index]
        self._index += 1
        return header, data

    def datalink(self):
        """Return datalink type."""
        return self._datalink

    def setfilter(self, bpf):
        """Set BPF filter (mock)."""
        pass


class MockPcapyHeader:
    """Mock pcapy packet header."""

    def __init__(self, length=100, ts_sec=1609459200, ts_usec=0):
        self._length = length
        self._ts_sec = ts_sec
        self._ts_usec = ts_usec

    def getlen(self):
        return self._length

    def getts(self):
        return (self._ts_sec, self._ts_usec)


class MockGeoIP:
    """Mock GeoIP lookup object."""

    def __init__(self):
        self.acc = False

    def check_file_dates(self):
        pass

    def geoip_country_lookup(self, ip):
        return "US"

    def geoip_asn_lookup(self, ip):
        return "AS15169 Google LLC"

    def geoip_location_lookup(self, ip):
        return ("US", 37.751, -97.822)


class MockOutput:
    """Mock output module for testing."""

    def __init__(self):
        self.written = []
        self.format = "%(data)s\n"
        self.format_fields = ["data"]
        self.nobuffer = False
        self.extra = False

    def setup(self):
        pass

    def close(self):
        pass

    def write(self, *args, **kwargs):
        self.written.append((args, kwargs))

    def set_format(self, fmt):
        self.format = fmt

    def set_oargs(self, **kwargs):
        pass


@pytest.fixture
def mock_geoip():
    """Fixture providing a mock GeoIP object."""
    return MockGeoIP()


@pytest.fixture
def mock_output():
    """Fixture providing a mock output module."""
    return MockOutput()


@pytest.fixture
def mock_pypacker_packet():
    """Fixture providing a basic mock pypacker packet."""
    return MockPypackerPacket()


@pytest.fixture
def mock_tcp_packet():
    """Fixture providing a mock TCP packet."""
    return MockPypackerPacket(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=54321,
        dst_port=80,
        protocol=6,
        data=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        tcp_flags=0x18,
        seq=1000,
        ack=1,
    )


@pytest.fixture
def mock_udp_packet():
    """Fixture providing a mock UDP packet."""
    return MockPypackerPacket(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=54321,
        dst_port=53,
        protocol=17,
        data=b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",
        tcp_flags=None,
        seq=None,
        ack=None,
    )


@pytest.fixture
def mock_fragmented_packet():
    """Fixture providing a mock fragmented IP packet."""
    return MockPypackerPacket(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        is_fragment=True,
        fragment_offset=0,
        fragment_id=12345,
        more_fragments=True,
        data=b"fragment1",
    )


@pytest.fixture
def mock_pcapy_capture():
    """Fixture providing a mock pcapy capture object."""
    return MockPcapyCapture()


@pytest.fixture
def mock_pcapy_header():
    """Fixture providing a mock pcapy header."""
    return MockPcapyHeader()


@pytest.fixture
def mock_dshell_packet(mock_geoip):
    """Fixture providing a mock Dshell Packet object."""
    with patch("dshell.core.geoip", mock_geoip):
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket()
        return Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)


@pytest.fixture
def mock_dshell_tcp_packet(mock_geoip):
    """Fixture providing a mock Dshell TCP Packet object."""
    with patch("dshell.core.geoip", mock_geoip):
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            protocol=6,
            data=b"HTTP request data",
            tcp_flags=0x18,
            seq=1000,
            ack=1,
        )
        return Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)


@pytest.fixture
def mock_dshell_udp_packet(mock_geoip):
    """Fixture providing a mock Dshell UDP Packet object."""
    with patch("dshell.core.geoip", mock_geoip):
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=53,
            protocol=17,
            data=b"DNS query data",
            tcp_flags=None,
            seq=None,
            ack=None,
        )
        return Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)


@pytest.fixture
def mock_connection(mock_geoip):
    """Fixture providing a mock Dshell Connection object."""
    with patch("dshell.core.geoip", mock_geoip):
        from dshell.core import Connection, Packet

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            protocol=6,
            data=b"Initial data",
            tcp_flags=0x02,
            seq=1000,
            ack=0,
        )
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)
        return Connection(packet)


@pytest.fixture
def mock_established_connection(mock_geoip):
    """Fixture providing a mock established Connection object."""
    with patch("dshell.core.geoip", mock_geoip):
        from dshell.core import Connection, Packet
        from pypacker.layer4 import tcp

        mock_syn = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            protocol=6,
            data=b"",
            tcp_flags=tcp.TH_SYN,
            seq=1000,
            ack=0,
        )
        syn_packet = Packet(pktlen=60, packet=mock_syn, timestamp=1609459200.0, frame=1)
        conn = Connection(syn_packet)

        mock_synack = MockPypackerPacket(
            src_ip="192.168.1.200",
            dst_ip="192.168.1.100",
            src_port=80,
            dst_port=12345,
            protocol=6,
            data=b"",
            tcp_flags=tcp.TH_SYN | tcp.TH_ACK,
            seq=2000,
            ack=1001,
        )
        synack_packet = Packet(
            pktlen=60, packet=mock_synack, timestamp=1609459200.1, frame=2
        )
        conn.add_packet(synack_packet)

        return conn


@pytest.fixture
def mock_closed_connection(mock_established_connection, mock_geoip):
    """Fixture providing a mock closed Connection object."""
    with patch("dshell.core.geoip", mock_geoip):
        from dshell.core import Packet
        from pypacker.layer4 import tcp

        conn = mock_established_connection

        mock_fin = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            protocol=6,
            data=b"",
            tcp_flags=tcp.TH_FIN | tcp.TH_ACK,
            seq=1001,
            ack=2001,
        )
        fin_packet = Packet(pktlen=60, packet=mock_fin, timestamp=1609459200.2, frame=3)
        conn.add_packet(fin_packet)

        mock_fin_ack = MockPypackerPacket(
            src_ip="192.168.1.200",
            dst_ip="192.168.1.100",
            src_port=80,
            dst_port=12345,
            protocol=6,
            data=b"",
            tcp_flags=tcp.TH_ACK,
            seq=2001,
            ack=1002,
        )
        fin_ack_packet = Packet(
            pktlen=60, packet=mock_fin_ack, timestamp=1609459200.3, frame=4
        )
        conn.add_packet(fin_ack_packet)

        mock_server_fin = MockPypackerPacket(
            src_ip="192.168.1.200",
            dst_ip="192.168.1.100",
            src_port=80,
            dst_port=12345,
            protocol=6,
            data=b"",
            tcp_flags=tcp.TH_FIN | tcp.TH_ACK,
            seq=2001,
            ack=1002,
        )
        server_fin_packet = Packet(
            pktlen=60, packet=mock_server_fin, timestamp=1609459200.4, frame=5
        )
        conn.add_packet(server_fin_packet)

        mock_final_ack = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            protocol=6,
            data=b"",
            tcp_flags=tcp.TH_ACK,
            seq=1002,
            ack=2002,
        )
        final_ack_packet = Packet(
            pktlen=60, packet=mock_final_ack, timestamp=1609459200.5, frame=6
        )
        conn.add_packet(final_ack_packet)

        return conn


@pytest.fixture
def mock_blob(mock_connection, mock_geoip):
    """Fixture providing a mock Dshell Blob object."""
    with patch("dshell.core.geoip", mock_geoip):
        from dshell.core import Blob, Packet

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            protocol=6,
            data=b"First segment",
            tcp_flags=0x18,
            seq=1000,
            ack=1,
        )
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)
        return Blob(mock_connection, packet)


@pytest.fixture
def mock_packet_plugin(mock_output, mock_geoip):
    """Fixture providing a mock PacketPlugin instance."""
    with patch("dshell.core.geoip", mock_geoip):
        from dshell.core import PacketPlugin

        plugin = PacketPlugin(name="test_plugin", description="Test plugin")
        plugin.out = mock_output
        return plugin


@pytest.fixture
def mock_connection_plugin(mock_output, mock_geoip):
    """Fixture providing a mock ConnectionPlugin instance."""
    with patch("dshell.core.geoip", mock_geoip):
        from dshell.core import ConnectionPlugin

        plugin = ConnectionPlugin(name="test_conn_plugin", description="Test connection plugin")
        plugin.out = mock_output
        return plugin


@pytest.fixture
def patched_geoip(mock_geoip):
    """Fixture that patches the global geoip object."""
    with patch("dshell.core.geoip", mock_geoip):
        yield mock_geoip


@pytest.fixture
def patched_pcapy():
    """Fixture that patches pcapy module."""
    mock_pcapy = MagicMock()
    mock_pcapy.compile = MagicMock(return_value=MagicMock())
    mock_pcapy.open_offline = MagicMock(return_value=MockPcapyCapture())
    mock_pcapy.open_live = MagicMock(return_value=MockPcapyCapture())
    mock_pcapy.PcapError = Exception

    with patch.dict("sys.modules", {"pcapy": mock_pcapy}):
        yield mock_pcapy


@pytest.fixture
def sample_tcp_stream_packets(mock_geoip):
    """Fixture providing a sequence of TCP packets forming a stream."""
    with patch("dshell.core.geoip", mock_geoip):
        from dshell.core import Packet

        packets = []

        mock_pkt1 = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            protocol=6,
            data=b"GET / HTTP/1.1\r\n",
            tcp_flags=0x18,
            seq=1000,
            ack=1,
        )
        packets.append(
            Packet(pktlen=100, packet=mock_pkt1, timestamp=1609459200.0, frame=1)
        )

        mock_pkt2 = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            protocol=6,
            data=b"Host: example.com\r\n\r\n",
            tcp_flags=0x18,
            seq=1016,
            ack=1,
        )
        packets.append(
            Packet(pktlen=100, packet=mock_pkt2, timestamp=1609459200.1, frame=2)
        )

        mock_pkt3 = MockPypackerPacket(
            src_ip="192.168.1.200",
            dst_ip="192.168.1.100",
            src_port=80,
            dst_port=12345,
            protocol=6,
            data=b"HTTP/1.1 200 OK\r\n",
            tcp_flags=0x18,
            seq=1,
            ack=1037,
        )
        packets.append(
            Packet(pktlen=100, packet=mock_pkt3, timestamp=1609459200.2, frame=3)
        )

        return packets


@pytest.fixture
def empty_plugin_chain():
    """Fixture that provides an empty plugin chain and resets it after test."""
    import dshell.decode as decode

    original_chain = decode.plugin_chain.copy()
    decode.plugin_chain = []
    yield decode.plugin_chain
    decode.plugin_chain = original_chain


@pytest.fixture
def temp_pcap_file(tmp_path):
    """Fixture providing a temporary PCAP file path."""
    pcap_file = tmp_path / "test.pcap"
    pcap_header = bytes([
        0xd4, 0xc3, 0xb2, 0xa1,
        0x02, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
    ])
    pcap_file.write_bytes(pcap_header)
    return str(pcap_file)


@pytest.fixture
def multiprocessing_value():
    """Fixture providing a multiprocessing Value for counter testing."""
    return Value("i", 0)


def create_mock_packet(
    src_ip="192.168.1.1",
    dst_ip="192.168.1.2",
    src_port=12345,
    dst_port=80,
    protocol=6,
    data=b"test",
    tcp_flags=0x18,
    seq=1000,
    ack=1,
    timestamp=1609459200.0,
    frame=1,
):
    """Helper function to create mock Dshell Packet objects."""
    from unittest.mock import patch

    mock_geoip = MockGeoIP()
    with patch("dshell.core.geoip", mock_geoip):
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            data=data,
            tcp_flags=tcp_flags,
            seq=seq,
            ack=ack,
        )
        return Packet(pktlen=len(data) + 54, packet=mock_pkt, timestamp=timestamp, frame=frame)

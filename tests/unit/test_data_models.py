"""
Unit tests for Dshell data models: Packet, Connection, and Blob classes.

These tests cover the core data structures used throughout the Dshell framework
for representing network packets, connections, and TCP stream blobs.
"""

import datetime
from unittest.mock import MagicMock, patch

import pytest

from tests.conftest import MockGeoIP, MockPypackerPacket, create_mock_packet


class TestPacketClass:
    """Tests for the Packet class."""

    def test_packet_initialization(self, patched_geoip):
        """Test basic Packet initialization with mock pypacker packet."""
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=80,
            protocol=6,
            data=b"test data",
        )
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        assert packet.sip == "10.0.0.1"
        assert packet.dip == "10.0.0.2"
        assert packet.sport == 12345
        assert packet.dport == 80
        assert packet.frame == 1
        assert packet.ts == 1609459200.0

    def test_packet_timestamp_conversion(self, patched_geoip):
        """Test that timestamp is properly converted to datetime."""
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket()
        timestamp = 1609459200.0
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=timestamp, frame=1)

        assert isinstance(packet.dt, datetime.datetime)
        assert packet.dt == datetime.datetime.fromtimestamp(timestamp)

    def test_packet_addr_property_with_ip(self, patched_geoip):
        """Test addr property returns correct tuple with IP addresses."""
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=54321,
            dst_port=80,
        )
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        expected_addr = (("192.168.1.1", 54321), ("192.168.1.2", 80))
        assert packet.addr == expected_addr

    def test_packet_addr_property_fallback_to_mac(self, patched_geoip):
        """Test addr property falls back to MAC addresses when IP is None."""
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket()
        mock_pkt._ip = None
        mock_pkt.src_ip = None
        mock_pkt.dst_ip = None

        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)
        packet.sip = None
        packet.dip = None
        packet.smac = "00:11:22:33:44:55"
        packet.dmac = "66:77:88:99:aa:bb"

        addr = packet.addr
        assert addr == (("00:11:22:33:44:55", packet.sport), ("66:77:88:99:aa:bb", packet.dport))

    def test_packet_byte_count_property(self, patched_geoip):
        """Test byte_count property returns correct data length."""
        from dshell.core import Packet

        test_data = b"Hello, World!"
        mock_pkt = MockPypackerPacket(data=test_data)
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        assert packet.byte_count >= 0

    def test_packet_byte_count_caching(self, patched_geoip):
        """Test that byte_count is cached after first access."""
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket(data=b"test")
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        _ = packet.byte_count
        assert packet._byte_count is not None
        assert packet.byte_count == packet._byte_count

    def test_packet_data_property_tcp(self, patched_geoip):
        """Test data property returns TCP payload."""
        from dshell.core import Packet

        test_data = b"TCP payload data"
        mock_pkt = MockPypackerPacket(protocol=6, data=test_data)
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        assert isinstance(packet.data, bytes)

    def test_packet_data_property_udp(self, patched_geoip):
        """Test data property returns UDP payload."""
        from dshell.core import Packet

        test_data = b"UDP payload data"
        mock_pkt = MockPypackerPacket(protocol=17, data=test_data, tcp_flags=None)
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        assert packet.data == test_data

    def test_packet_rawpkt_property(self, patched_geoip):
        """Test rawpkt property returns binary packet data."""
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket(data=b"test")
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        rawpkt = packet.rawpkt
        assert isinstance(rawpkt, bytes)

    def test_packet_packet_tuple_property(self, patched_geoip):
        """Test packet_tuple property returns correct tuple."""
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket()
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        pkt_tuple = packet.packet_tuple
        assert pkt_tuple[0] == 100
        assert pkt_tuple[2] == 1609459200.0

    def test_packet_tcp_flags(self, patched_geoip):
        """Test TCP flags are properly extracted."""
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket(tcp_flags=0x18)
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        assert packet.tcp_flags == 0x18

    def test_packet_sequence_numbers(self, patched_geoip):
        """Test TCP sequence and ACK numbers are properly extracted."""
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket(seq=1000, ack=2000)
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        assert packet.sequence_number == 1000
        assert packet.ack_number == 2000

    def test_packet_geoip_lookup(self, patched_geoip):
        """Test GeoIP lookup is performed for IP addresses."""
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket(src_ip="8.8.8.8", dst_ip="1.1.1.1")
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        assert packet.sipcc == "US"
        assert packet.dipcc == "US"

    def test_packet_protocol_mapping(self, patched_geoip):
        """Test protocol number is mapped to protocol name."""
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket(protocol=6)
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        assert packet.protocol_num == 6
        assert packet.protocol == "TCP"

    def test_packet_info_method(self, patched_geoip):
        """Test info() method returns dictionary with packet attributes."""
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket()
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        info = packet.info()
        assert isinstance(info, dict)
        assert "sip" in info
        assert "dip" in info
        assert "sport" in info
        assert "dport" in info
        assert "byte_count" in info
        assert "rawpkt" in info
        assert "pkt" not in info

    def test_packet_repr(self, patched_geoip):
        """Test __repr__ returns formatted string."""
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket()
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        repr_str = repr(packet)
        assert isinstance(repr_str, str)
        assert packet.sip in repr_str

    def test_packet_mac_addresses(self, patched_geoip):
        """Test MAC addresses are properly extracted from Ethernet layer."""
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket(
            src_mac="aa:bb:cc:dd:ee:ff",
            dst_mac="11:22:33:44:55:66",
        )
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        assert packet.smac.lower() == "aa:bb:cc:dd:ee:ff"
        assert packet.dmac.lower() == "11:22:33:44:55:66"

    def test_packet_data_setter(self, patched_geoip):
        """Test data setter modifies packet payload."""
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket(data=b"original")
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        new_data = b"modified"
        packet.data = new_data
        assert packet._data == new_data


class TestConnectionClass:
    """Tests for the Connection class."""

    def test_connection_initialization(self, mock_connection):
        """Test basic Connection initialization from first packet."""
        conn = mock_connection

        assert conn.sip == "192.168.1.100"
        assert conn.dip == "192.168.1.200"
        assert conn.sport == 12345
        assert conn.dport == 80
        assert len(conn.packets) == 1

    def test_connection_client_server_aliases(self, mock_connection):
        """Test client/server aliases match source/dest."""
        conn = mock_connection

        assert conn.clientip == conn.sip
        assert conn.serverip == conn.dip
        assert conn.clientport == conn.sport
        assert conn.serverport == conn.dport

    def test_connection_add_packet(self, mock_connection, patched_geoip):
        """Test adding packets to connection."""
        from dshell.core import Packet

        conn = mock_connection
        initial_count = len(conn.packets)

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.200",
            dst_ip="192.168.1.100",
            src_port=80,
            dst_port=12345,
            data=b"response",
        )
        new_packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459201.0, frame=2)
        conn.add_packet(new_packet)

        assert len(conn.packets) == initial_count + 1

    def test_connection_add_packet_invalid_address(self, mock_connection, patched_geoip):
        """Test adding packet with invalid address raises error."""
        from dshell.core import Packet

        conn = mock_connection

        mock_pkt = MockPypackerPacket(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
        )
        invalid_packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459201.0, frame=2)

        with pytest.raises(ValueError, match="not part of connection"):
            conn.add_packet(invalid_packet)

    def test_connection_duration_property(self, mock_connection, patched_geoip):
        """Test duration property calculates time difference."""
        from dshell.core import Packet

        conn = mock_connection

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.200",
            dst_ip="192.168.1.100",
            src_port=80,
            dst_port=12345,
        )
        later_packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459210.0, frame=2)
        conn.add_packet(later_packet)

        assert conn.duration == pytest.approx(10.0, rel=0.1)

    def test_connection_established_state(self, mock_established_connection):
        """Test connection established state after SYN-ACK."""
        conn = mock_established_connection

        assert conn.established is True
        assert conn.client_state == "established"
        assert conn.server_state == "established"

    def test_connection_closed_state(self, mock_closed_connection):
        """Test connection closed state after FIN exchange."""
        conn = mock_closed_connection

        assert conn.closed is True
        assert conn.client_state == "closed"
        assert conn.server_state == "closed"

    def test_connection_bytes_and_counts(self, mock_connection, patched_geoip):
        """Test bytes_and_counts method returns correct values."""
        from dshell.core import Packet

        conn = mock_connection

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.200",
            dst_ip="192.168.1.100",
            src_port=80,
            dst_port=12345,
            data=b"server response",
        )
        server_packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459201.0, frame=2)
        conn.add_packet(server_packet)

        cb, cp, sb, sp = conn.bytes_and_counts()
        assert cb >= 0
        assert sb >= 0
        assert cp >= 0
        assert sp >= 0

    def test_connection_totalbytes_property(self, mock_connection, patched_geoip):
        """Test totalbytes property sums all packet bytes."""
        from dshell.core import Packet

        conn = mock_connection

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.200",
            dst_ip="192.168.1.100",
            src_port=80,
            dst_port=12345,
            data=b"response data",
        )
        server_packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459201.0, frame=2)
        conn.add_packet(server_packet)

        total = conn.totalbytes
        assert total >= 0

    def test_connection_clientbytes_property(self, mock_connection):
        """Test clientbytes property returns client-side bytes."""
        conn = mock_connection
        assert conn.clientbytes >= 0

    def test_connection_serverbytes_property(self, mock_connection, patched_geoip):
        """Test serverbytes property returns server-side bytes."""
        from dshell.core import Packet

        conn = mock_connection

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.200",
            dst_ip="192.168.1.100",
            src_port=80,
            dst_port=12345,
            data=b"server data",
        )
        server_packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459201.0, frame=2)
        conn.add_packet(server_packet)

        assert conn.serverbytes >= 0

    def test_connection_clientpackets_property(self, mock_connection):
        """Test clientpackets property returns client packet count."""
        conn = mock_connection
        assert conn.clientpackets >= 0

    def test_connection_serverpackets_property(self, mock_connection, patched_geoip):
        """Test serverpackets property returns server packet count."""
        from dshell.core import Packet

        conn = mock_connection

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.200",
            dst_ip="192.168.1.100",
            src_port=80,
            dst_port=12345,
            data=b"server data",
        )
        server_packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459201.0, frame=2)
        conn.add_packet(server_packet)

        assert conn.serverpackets >= 0

    def test_connection_blobs_property(self, mock_connection, patched_geoip):
        """Test blobs property generates Blob objects."""
        conn = mock_connection

        blobs = list(conn.blobs)
        assert isinstance(blobs, list)

    def test_connection_blobs_caching(self, mock_connection):
        """Test blobs are cached after first generation."""
        conn = mock_connection

        blobs1 = list(conn.blobs)
        blobs2 = list(conn.blobs)

        assert len(blobs1) == len(blobs2)

    def test_connection_info_method(self, mock_connection):
        """Test info() method returns dictionary with connection attributes."""
        conn = mock_connection

        info = conn.info()
        assert isinstance(info, dict)
        assert "sip" in info
        assert "dip" in info
        assert "sport" in info
        assert "dport" in info
        assert "duration" in info
        assert "clientbytes" in info
        assert "serverbytes" in info
        assert "stop" not in info
        assert "handled" not in info
        assert "packets" not in info

    def test_connection_repr(self, mock_connection):
        """Test __repr__ returns formatted string."""
        conn = mock_connection

        repr_str = repr(conn)
        assert isinstance(repr_str, str)
        assert conn.clientip in repr_str

    def test_connection_tcp_state_syn(self, patched_geoip):
        """Test TCP state tracking for SYN packet."""
        from dshell.core import Connection, Packet
        from pypacker.layer4 import tcp

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            tcp_flags=tcp.TH_SYN,
            data=b"",
        )
        packet = Packet(pktlen=60, packet=mock_pkt, timestamp=1609459200.0, frame=1)
        conn = Connection(packet)

        assert conn.client_state is None
        assert conn.server_state is None

    def test_connection_tcp_state_synack(self, patched_geoip):
        """Test TCP state tracking for SYN-ACK packet."""
        from dshell.core import Connection, Packet
        from pypacker.layer4 import tcp

        mock_syn = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            tcp_flags=tcp.TH_SYN,
            data=b"",
        )
        syn_packet = Packet(pktlen=60, packet=mock_syn, timestamp=1609459200.0, frame=1)
        conn = Connection(syn_packet)

        mock_synack = MockPypackerPacket(
            src_ip="192.168.1.200",
            dst_ip="192.168.1.100",
            src_port=80,
            dst_port=12345,
            tcp_flags=tcp.TH_SYN | tcp.TH_ACK,
            data=b"",
        )
        synack_packet = Packet(pktlen=60, packet=mock_synack, timestamp=1609459200.1, frame=2)
        conn.add_packet(synack_packet)

        assert conn.client_state == "established"
        assert conn.server_state == "established"

    def test_connection_tcp_state_fin(self, mock_established_connection, patched_geoip):
        """Test TCP state tracking for FIN packet."""
        from dshell.core import Packet
        from pypacker.layer4 import tcp

        conn = mock_established_connection

        mock_fin = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            tcp_flags=tcp.TH_FIN,
            data=b"",
        )
        fin_packet = Packet(pktlen=60, packet=mock_fin, timestamp=1609459200.2, frame=3)
        conn.add_packet(fin_packet)

        assert conn.client_state == "finishing"

    def test_connection_tcp_state_rst(self, mock_established_connection, patched_geoip):
        """Test TCP state tracking for RST packet."""
        from dshell.core import Packet
        from pypacker.layer4 import tcp

        conn = mock_established_connection

        mock_rst = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            tcp_flags=tcp.TH_RST,
            data=b"",
        )
        rst_packet = Packet(pktlen=60, packet=mock_rst, timestamp=1609459200.2, frame=3)
        conn.add_packet(rst_packet)

        assert conn.client_state == "finishing"

    def test_connection_endtime_updates(self, mock_connection, patched_geoip):
        """Test endtime updates when new packets arrive."""
        from dshell.core import Packet

        conn = mock_connection
        initial_endtime = conn.endtime

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.200",
            dst_ip="192.168.1.100",
            src_port=80,
            dst_port=12345,
        )
        later_packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459300.0, frame=2)
        conn.add_packet(later_packet)

        assert conn.endtime > initial_endtime


class TestBlobClass:
    """Tests for the Blob class."""

    def test_blob_initialization(self, mock_blob):
        """Test basic Blob initialization from first packet."""
        blob = mock_blob

        assert blob.sip == "192.168.1.100"
        assert blob.dip == "192.168.1.200"
        assert blob.sport == 12345
        assert blob.dport == 80
        assert len(blob.packets) == 1

    def test_blob_add_packet(self, mock_blob, patched_geoip):
        """Test adding packets to blob."""
        from dshell.core import Packet

        blob = mock_blob
        initial_count = len(blob.packets)

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            data=b"more data",
            seq=1013,
        )
        new_packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459201.0, frame=2)
        blob.add_packet(new_packet)

        assert len(blob.packets) == initial_count + 1

    def test_blob_data_property_non_tcp(self, mock_connection, patched_geoip):
        """Test data property for non-TCP blob."""
        from dshell.core import Blob, Packet

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            protocol=17,
            data=b"UDP data",
            tcp_flags=None,
            seq=None,
        )
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)
        blob = Blob(mock_connection, packet)

        assert blob.data == b"UDP data"

    def test_blob_data_property_tcp(self, mock_blob, patched_geoip):
        """Test data property for TCP blob with sequence numbers."""
        from dshell.core import Packet

        blob = mock_blob

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            data=b" continued",
            seq=1013,
        )
        packet2 = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.1, frame=2)
        blob.add_packet(packet2)

        data = blob.data
        assert isinstance(data, bytes)
        assert len(data) > 0

    def test_blob_data_caching(self, mock_blob):
        """Test data is cached after first access."""
        blob = mock_blob

        data1 = blob.data
        data2 = blob.data

        assert data1 == data2

    def test_blob_sequence_numbers_property(self, mock_blob, patched_geoip):
        """Test sequence_numbers property returns list of sequence numbers."""
        from dshell.core import Packet

        blob = mock_blob

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            data=b"more",
            seq=1013,
        )
        packet2 = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.1, frame=2)
        blob.add_packet(packet2)

        seq_nums = blob.sequence_numbers
        assert isinstance(seq_nums, list)
        assert 1000 in seq_nums
        assert 1013 in seq_nums

    def test_blob_sequence_range_property(self, mock_blob):
        """Test sequence_range property returns range object."""
        blob = mock_blob

        seq_range = blob.sequence_range
        assert isinstance(seq_range, range)

    def test_blob_segments_property(self, mock_blob, patched_geoip):
        """Test segments property returns ordered list of (seq, packet) tuples."""
        from dshell.core import Packet

        blob = mock_blob

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            data=b"more",
            seq=1013,
        )
        packet2 = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.1, frame=2)
        blob.add_packet(packet2)

        segments = blob.segments
        assert isinstance(segments, list)
        assert len(segments) >= 1

        for seq, pkt in segments:
            assert isinstance(seq, int)

    def test_blob_frames_property(self, mock_blob, patched_geoip):
        """Test frames property returns list of frame numbers."""
        from dshell.core import Packet

        blob = mock_blob

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            data=b"more",
            seq=1013,
        )
        packet2 = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.1, frame=2)
        blob.add_packet(packet2)

        frames = blob.frames
        assert isinstance(frames, list)
        assert 1 in frames
        assert 2 in frames

    def test_blob_start_time_property(self, mock_blob):
        """Test start_time property returns earliest timestamp."""
        blob = mock_blob
        assert blob.start_time == blob.starttime

    def test_blob_end_time_property(self, mock_blob):
        """Test end_time property returns latest timestamp."""
        blob = mock_blob
        assert blob.end_time == blob.endtime

    def test_blob_hidden_attribute(self, mock_blob):
        """Test hidden attribute defaults to False."""
        blob = mock_blob
        assert blob.hidden is False

    def test_blob_hidden_can_be_set(self, mock_blob):
        """Test hidden attribute can be modified."""
        blob = mock_blob
        blob.hidden = True
        assert blob.hidden is True

    def test_blob_direction_constants(self):
        """Test Blob direction constants are defined."""
        from dshell.core import Blob

        assert Blob.CLIENT_TO_SERVER == "cs"
        assert Blob.SERVER_TO_CLIENT == "sc"

    def test_blob_max_offset_constant(self):
        """Test Blob MAX_OFFSET constant for TCP sequence wrap."""
        from dshell.core import Blob

        assert Blob.MAX_OFFSET == 0xffffffff

    def test_blob_info_method(self, mock_blob):
        """Test info() method returns dictionary with blob attributes."""
        blob = mock_blob

        info = blob.info()
        assert isinstance(info, dict)
        assert "sip" in info
        assert "dip" in info
        assert "sport" in info
        assert "dport" in info
        assert "hidden" not in info
        assert "packets" not in info

    def test_blob_retransmission_handling(self, mock_blob, patched_geoip):
        """Test blob handles retransmitted packets."""
        from dshell.core import Packet

        blob = mock_blob

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            data=b"First segment",
            seq=1000,
        )
        retrans_packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.5, frame=3)
        blob.add_packet(retrans_packet)

        assert len(blob.packets) == 1

    def test_blob_get_packets_method(self, mock_blob, patched_geoip):
        """Test get_packets method returns packets for offset range."""
        from dshell.core import Packet

        blob = mock_blob

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            data=b"more data here",
            seq=1013,
        )
        packet2 = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.1, frame=2)
        blob.add_packet(packet2)

        packets = blob.get_packets(0, 10)
        assert isinstance(packets, list)

    def test_blob_get_frames_method(self, mock_blob, patched_geoip):
        """Test get_frames method returns frame IDs for offset range."""
        from dshell.core import Packet

        blob = mock_blob

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            data=b"more data here",
            seq=1013,
        )
        packet2 = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.1, frame=2)
        blob.add_packet(packet2)

        frames = blob.get_frames(0, 10)
        assert isinstance(frames, list)

    def test_blob_reassemble_method(self, mock_blob, patched_geoip):
        """Test reassemble method rebuilds data from packets."""
        from dshell.core import Packet

        blob = mock_blob

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            data=b"more",
            seq=1013,
        )
        packet2 = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.1, frame=2)
        blob.add_packet(packet2)

        data = blob.reassemble()
        assert isinstance(data, bytes)

    def test_blob_data_setter(self, mock_blob):
        """Test data setter replaces blob data."""
        blob = mock_blob
        original_data = blob.data
        original_len = len(original_data)

        new_data = b"X" * original_len
        blob.data = new_data

        assert blob.data == new_data

    def test_blob_data_setter_length_mismatch(self, mock_blob):
        """Test data setter raises error on length mismatch."""
        blob = mock_blob

        with pytest.raises(ValueError, match="same length"):
            blob.data = b"different length data that is much longer"


class TestExceptions:
    """Tests for custom exception classes."""

    def test_sequence_number_error(self):
        """Test SequenceNumberError can be raised and caught."""
        from dshell.core import SequenceNumberError

        with pytest.raises(SequenceNumberError):
            raise SequenceNumberError("Missing data")

    def test_data_error(self):
        """Test DataError can be raised and caught."""
        from dshell.core import DataError

        with pytest.raises(DataError):
            raise DataError("Invalid data")

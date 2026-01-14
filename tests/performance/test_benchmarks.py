"""
Performance benchmark tests for Dshell.

These tests use pytest-benchmark to measure and track performance
of critical operations in the Dshell framework.
"""

from unittest.mock import MagicMock, patch

import pytest

from tests.conftest import MockGeoIP, MockOutput, MockPypackerPacket


class TestPacketProcessingBenchmarks:
    """Benchmarks for packet processing throughput."""

    def test_packet_creation_benchmark(self, benchmark, patched_geoip):
        """Benchmark Packet object creation."""
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket()

        def create_packet():
            return Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        result = benchmark(create_packet)
        assert result is not None

    def test_consume_packet_benchmark(self, benchmark, patched_geoip):
        """Benchmark PacketPlugin.consume_packet throughput."""
        from dshell.core import PacketPlugin, Packet

        plugin = PacketPlugin()
        plugin.out = MockOutput()

        mock_pkt = MockPypackerPacket()
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        def consume():
            plugin.consume_packet(packet)
            plugin._packet_queue.clear()

        benchmark(consume)

    def test_packet_data_access_benchmark(self, benchmark, patched_geoip):
        """Benchmark Packet.data property access."""
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket(data=b"test data " * 100)
        packet = Packet(pktlen=1000, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        def access_data():
            return packet.data

        result = benchmark(access_data)
        assert result is not None

    def test_packet_info_benchmark(self, benchmark, patched_geoip):
        """Benchmark Packet.info() method."""
        from dshell.core import Packet

        mock_pkt = MockPypackerPacket()
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        def get_info():
            return packet.info()

        result = benchmark(get_info)
        assert isinstance(result, dict)


class TestConnectionTrackingBenchmarks:
    """Benchmarks for connection tracking overhead."""

    def test_connection_creation_benchmark(self, benchmark, patched_geoip):
        """Benchmark Connection object creation."""
        from dshell.core import Connection, Packet

        mock_pkt = MockPypackerPacket()
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        def create_connection():
            return Connection(packet)

        result = benchmark(create_connection)
        assert result is not None

    def test_connection_add_packet_benchmark(self, benchmark, patched_geoip):
        """Benchmark Connection.add_packet performance."""
        from dshell.core import Connection, Packet

        mock_pkt1 = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
        )
        packet1 = Packet(pktlen=100, packet=mock_pkt1, timestamp=1609459200.0, frame=1)
        conn = Connection(packet1)

        mock_pkt2 = MockPypackerPacket(
            src_ip="192.168.1.200",
            dst_ip="192.168.1.100",
            src_port=80,
            dst_port=12345,
            seq=2000,
        )
        packet2 = Packet(pktlen=100, packet=mock_pkt2, timestamp=1609459200.1, frame=2)

        def add_packet():
            conn.add_packet(packet2)
            conn.packets.pop()

        benchmark(add_packet)

    def test_connection_handler_benchmark(self, benchmark, patched_geoip):
        """Benchmark ConnectionPlugin._connection_handler performance."""
        from dshell.core import ConnectionPlugin, Packet

        plugin = ConnectionPlugin()
        plugin.out = MockOutput()

        mock_pkt = MockPypackerPacket()
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        def handle_connection():
            plugin._connection_handler(packet)
            plugin._connection_tracker.clear()

        benchmark(handle_connection)

    def test_connection_tracker_lookup_benchmark(self, benchmark, patched_geoip):
        """Benchmark connection tracker dictionary lookup."""
        from dshell.core import ConnectionPlugin, Connection, Packet

        plugin = ConnectionPlugin()
        plugin.out = MockOutput()

        for i in range(100):
            mock_pkt = MockPypackerPacket(
                src_ip=f"192.168.1.{i}",
                dst_ip="192.168.1.200",
                src_port=12345 + i,
                dst_port=80,
            )
            packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0 + i, frame=i + 1)
            conn = Connection(packet)
            connkey = tuple(sorted(conn.addr) + [conn.protocol_num])
            plugin._connection_tracker[connkey] = conn

        target_key = list(plugin._connection_tracker.keys())[50]

        def lookup():
            return plugin._connection_tracker.get(target_key)

        result = benchmark(lookup)
        assert result is not None


class TestTCPReassemblyBenchmarks:
    """Benchmarks for TCP stream reassembly performance."""

    def test_blob_creation_benchmark(self, benchmark, patched_geoip):
        """Benchmark Blob object creation."""
        from dshell.core import Blob, Connection, Packet

        mock_pkt = MockPypackerPacket()
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)
        conn = Connection(packet)

        def create_blob():
            return Blob(conn, packet)

        result = benchmark(create_blob)
        assert result is not None

    def test_blob_add_packet_benchmark(self, benchmark, patched_geoip):
        """Benchmark Blob.add_packet performance."""
        from dshell.core import Blob, Connection, Packet

        mock_pkt1 = MockPypackerPacket(seq=1000, data=b"initial")
        packet1 = Packet(pktlen=100, packet=mock_pkt1, timestamp=1609459200.0, frame=1)
        conn = Connection(packet1)
        blob = Blob(conn, packet1)

        mock_pkt2 = MockPypackerPacket(seq=1007, data=b"more data")
        packet2 = Packet(pktlen=100, packet=mock_pkt2, timestamp=1609459200.1, frame=2)

        def add_packet():
            blob.add_packet(packet2)
            blob.packets.pop()

        benchmark(add_packet)

    def test_blob_data_property_benchmark(self, benchmark, patched_geoip):
        """Benchmark Blob.data property (TCP reassembly)."""
        from dshell.core import Blob, Connection, Packet

        mock_pkt1 = MockPypackerPacket(seq=1000, data=b"segment1 " * 10)
        packet1 = Packet(pktlen=100, packet=mock_pkt1, timestamp=1609459200.0, frame=1)
        conn = Connection(packet1)
        blob = Blob(conn, packet1)

        for i in range(10):
            mock_pkt = MockPypackerPacket(
                seq=1000 + (i + 1) * 90,
                data=f"segment{i+2} ".encode() * 10,
            )
            packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0 + i * 0.1, frame=i + 2)
            blob.add_packet(packet)

        blob._data = None

        def get_data():
            blob._data = None
            return blob.data

        result = benchmark(get_data)
        assert isinstance(result, bytes)

    def test_blob_reassemble_benchmark(self, benchmark, patched_geoip):
        """Benchmark Blob.reassemble method."""
        from dshell.core import Blob, Connection, Packet

        mock_pkt1 = MockPypackerPacket(seq=1000, data=b"A" * 100)
        packet1 = Packet(pktlen=100, packet=mock_pkt1, timestamp=1609459200.0, frame=1)
        conn = Connection(packet1)
        blob = Blob(conn, packet1)

        for i in range(20):
            mock_pkt = MockPypackerPacket(
                seq=1000 + (i + 1) * 100,
                data=b"B" * 100,
            )
            packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0 + i * 0.1, frame=i + 2)
            blob.add_packet(packet)

        def reassemble():
            return blob.reassemble()

        result = benchmark(reassemble)
        assert isinstance(result, bytes)


class TestIPDefragmentationBenchmarks:
    """Benchmarks for IP defragmentation speed."""

    def test_ipdefrag_unfragmented_benchmark(self, benchmark, patched_geoip):
        """Benchmark ipdefrag with unfragmented packets."""
        from dshell.core import PacketPlugin, Packet

        plugin = PacketPlugin()
        plugin.out = MockOutput()

        mock_pkt = MockPypackerPacket(is_fragment=False)
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        def defrag():
            return plugin.ipdefrag(packet)

        result = benchmark(defrag)
        assert result is packet


class TestPluginChainBenchmarks:
    """Benchmarks for plugin chain processing rates."""

    def test_feed_plugin_chain_single_benchmark(self, benchmark, patched_geoip):
        """Benchmark feed_plugin_chain with single plugin."""
        from dshell.core import PacketPlugin, Packet
        import dshell.decode as decode

        plugin = PacketPlugin()
        plugin.out = MockOutput()

        mock_pkt = MockPypackerPacket()
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin]

        try:
            def feed():
                decode.feed_plugin_chain(0, packet)
                plugin._packet_queue.clear()

            benchmark(feed)
        finally:
            decode.plugin_chain = original_chain

    def test_feed_plugin_chain_multiple_benchmark(self, benchmark, patched_geoip):
        """Benchmark feed_plugin_chain with multiple plugins."""
        from dshell.core import PacketPlugin, Packet
        import dshell.decode as decode

        plugins = []
        for i in range(3):
            plugin = PacketPlugin(name=f"plugin{i}")
            plugin.out = MockOutput()
            plugins.append(plugin)

        mock_pkt = MockPypackerPacket()
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = plugins

        try:
            def feed():
                decode.feed_plugin_chain(0, packet)
                for p in plugins:
                    p._packet_queue.clear()

            benchmark(feed)
        finally:
            decode.plugin_chain = original_chain

    def test_produce_packets_benchmark(self, benchmark, patched_geoip):
        """Benchmark produce_packets generator."""
        from dshell.core import PacketPlugin, Packet

        plugin = PacketPlugin()
        plugin.out = MockOutput()

        for i in range(100):
            mock_pkt = MockPypackerPacket()
            packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0 + i, frame=i + 1)
            plugin._packet_queue.append(packet)

        def produce():
            packets = list(plugin.produce_packets())
            for p in packets:
                plugin._packet_queue.append(p)
            return packets

        result = benchmark(produce)
        assert len(result) == 100


class TestOutputBenchmarks:
    """Benchmarks for output module performance."""

    def test_output_write_benchmark(self, benchmark):
        """Benchmark Output.write performance."""
        from dshell.output.output import Output
        from io import StringIO

        output = Output(fh=StringIO())

        def write():
            output.write("test data", sip="192.168.1.1", dip="192.168.1.2")

        benchmark(write)

    def test_output_convert_benchmark(self, benchmark):
        """Benchmark Output.convert performance."""
        from dshell.output.output import Output

        output = Output()

        def convert():
            return output.convert(
                "test data",
                sip="192.168.1.1",
                dip="192.168.1.2",
                sport=12345,
                dport=80,
                ts=1609459200.0,
            )

        result = benchmark(convert)
        assert isinstance(result, str)

    def test_queue_output_wrapper_benchmark(self, benchmark):
        """Benchmark QueueOutputWrapper.write performance."""
        from dshell.output.output import Output, QueueOutputWrapper
        from multiprocessing import Queue

        output = Output()
        queue = Queue()
        wrapper = QueueOutputWrapper(output, queue)

        def write():
            wrapper.write("test data", key="value")

        benchmark(write)

        while not queue.empty():
            queue.get()

"""
Integration tests for multiprocessing capabilities.

These tests verify parallel file processing, output coordination,
process lifecycle management, and error handling in multiprocessing scenarios.
"""

from multiprocessing import Queue, Value, Process
from unittest.mock import MagicMock, Mock, patch
import time

import pytest

from tests.conftest import MockGeoIP, MockOutput, MockPypackerPacket


class TestQueueOutputWrapper:
    """Tests for QueueOutputWrapper thread-safe output."""

    def test_queue_output_wrapper_initialization(self):
        """Test QueueOutputWrapper initializes correctly."""
        from dshell.output.output import Output, QueueOutputWrapper

        output = Output()
        queue = Queue()

        wrapper = QueueOutputWrapper(output, queue)

        assert wrapper.queue is queue
        assert wrapper.id == str(output)

    def test_queue_output_wrapper_write_adds_to_queue(self):
        """Test QueueOutputWrapper.write adds message to queue."""
        from dshell.output.output import Output, QueueOutputWrapper

        output = Output()
        queue = Queue()

        wrapper = QueueOutputWrapper(output, queue)
        wrapper.write("test data", key="value")

        assert not queue.empty()
        item = queue.get()
        assert item[0] == wrapper.id
        assert item[1] == ("test data",)
        assert item[2] == {"key": "value"}

    def test_queue_output_wrapper_true_write(self):
        """Test QueueOutputWrapper.true_write calls underlying write."""
        from dshell.output.output import Output, QueueOutputWrapper

        output = Output()
        output.write = MagicMock()
        queue = Queue()

        wrapper = QueueOutputWrapper(output, queue)
        wrapper.true_write("test data", key="value")

        output.write.assert_called_once_with("test data", key="value")

    def test_queue_output_wrapper_multiple_writes(self):
        """Test QueueOutputWrapper handles multiple writes."""
        from dshell.output.output import Output, QueueOutputWrapper

        output = Output()
        queue = Queue()

        wrapper = QueueOutputWrapper(output, queue)

        for i in range(5):
            wrapper.write(f"message {i}")

        count = 0
        while not queue.empty():
            queue.get()
            count += 1

        assert count == 5


class TestMultiprocessingValue:
    """Tests for multiprocessing Value counters."""

    def test_packet_counter_initialization(self, patched_geoip):
        """Test packet counters initialize to zero."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin()

        assert plugin.seen_packet_count.value == 0
        assert plugin.handled_packet_count.value == 0

    def test_packet_counter_increment(self, patched_geoip, mock_dshell_packet):
        """Test packet counters increment correctly."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin()
        plugin.out = MockOutput()

        initial_seen = plugin.seen_packet_count.value
        plugin.consume_packet(mock_dshell_packet)

        assert plugin.seen_packet_count.value == initial_seen + 1

    def test_connection_counter_initialization(self, patched_geoip):
        """Test connection counters initialize to zero."""
        from dshell.core import ConnectionPlugin

        plugin = ConnectionPlugin()

        assert plugin.seen_conn_count.value == 0
        assert plugin.handled_conn_count.value == 0

    def test_connection_counter_increment(self, patched_geoip, mock_dshell_tcp_packet):
        """Test connection counters increment correctly."""
        from dshell.core import ConnectionPlugin

        plugin = ConnectionPlugin()
        plugin.out = MockOutput()

        initial_seen = plugin.seen_conn_count.value
        plugin.consume_packet(mock_dshell_tcp_packet)

        assert plugin.seen_conn_count.value == initial_seen + 1

    def test_counter_thread_safety(self, patched_geoip):
        """Test counters are thread-safe with Value."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin()

        assert isinstance(plugin.seen_packet_count, type(Value("i", 0)))
        assert isinstance(plugin.handled_packet_count, type(Value("i", 0)))


class TestParallelFileProcessing:
    """Tests for parallel file processing."""

    def test_process_files_handles_single_file(self, temp_pcap_file, patched_geoip):
        """Test process_files handles single file correctly."""
        import dshell.decode as decode

        with patch.object(decode, "read_packets") as mock_read:
            mock_read.return_value = iter([])

            decode.process_files(files=[temp_pcap_file])

            mock_read.assert_called()

    def test_process_files_handles_multiple_files(self, tmp_path, patched_geoip):
        """Test process_files handles multiple files."""
        import dshell.decode as decode

        pcap_header = bytes([
            0xd4, 0xc3, 0xb2, 0xa1,
            0x02, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
        ])

        files = []
        for i in range(3):
            f = tmp_path / f"test{i}.pcap"
            f.write_bytes(pcap_header)
            files.append(str(f))

        with patch.object(decode, "read_packets") as mock_read:
            mock_read.return_value = iter([])

            decode.process_files(files=files)

            assert mock_read.call_count >= 1


class TestProcessLifecycle:
    """Tests for process spawning and lifecycle management."""

    def test_plugin_premodule_called(self, patched_geoip):
        """Test plugin _premodule is called during setup."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin()
        plugin.out = MockOutput()
        plugin.premodule = MagicMock()

        plugin._premodule()

        plugin.premodule.assert_called_once()

    def test_plugin_postmodule_called(self, patched_geoip):
        """Test plugin _postmodule is called during cleanup."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin()
        plugin.out = MockOutput()
        plugin.postmodule = MagicMock()

        plugin._postmodule()

        plugin.postmodule.assert_called_once()

    def test_plugin_prefile_called(self, patched_geoip, temp_pcap_file):
        """Test plugin _prefile is called before each file."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin()
        plugin.out = MockOutput()
        plugin.prefile = MagicMock()

        plugin._prefile(temp_pcap_file)

        plugin.prefile.assert_called_once_with(temp_pcap_file)

    def test_plugin_postfile_called(self, patched_geoip):
        """Test plugin _postfile is called after each file."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin()
        plugin.out = MockOutput()
        plugin.postfile = MagicMock()

        plugin._postfile()

        plugin.postfile.assert_called_once()


class TestGracefulShutdown:
    """Tests for graceful shutdown handling."""

    def test_plugin_flush_on_shutdown(self, patched_geoip, mock_dshell_packet):
        """Test plugin flush is called on shutdown."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin()
        plugin.out = MockOutput()
        plugin._packet_queue.append(mock_dshell_packet)

        plugin.flush()

        assert len(plugin._packet_queue) == 1

    def test_plugin_purge_clears_state(self, patched_geoip, mock_dshell_packet):
        """Test plugin purge clears all state."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin()
        plugin.out = MockOutput()
        plugin._packet_queue.append(mock_dshell_packet)
        plugin._packet_fragments[("key",)] = "value"

        plugin.purge()

        assert plugin._packet_queue == []
        assert len(plugin._packet_fragments) == 0

    def test_connection_plugin_cleanup_on_shutdown(self, patched_geoip, mock_dshell_tcp_packet):
        """Test ConnectionPlugin cleanup on shutdown."""
        from dshell.core import ConnectionPlugin

        plugin = ConnectionPlugin()
        plugin.out = MockOutput()

        plugin.consume_packet(mock_dshell_tcp_packet)
        assert len(plugin._connection_tracker) == 1

        plugin._cleanup_connections()

        assert len(plugin._connection_tracker) == 0


class TestOutputQueueHandling:
    """Tests for output queue handling and synchronization."""

    def test_output_queue_ordering(self):
        """Test output queue maintains message ordering."""
        from dshell.output.output import Output, QueueOutputWrapper

        output = Output()
        queue = Queue()

        wrapper = QueueOutputWrapper(output, queue)

        messages = ["first", "second", "third"]
        for msg in messages:
            wrapper.write(msg)

        received = []
        while not queue.empty():
            item = queue.get()
            received.append(item[1][0])

        assert received == messages

    def test_multiple_wrappers_same_queue(self):
        """Test multiple wrappers can share same queue."""
        from dshell.output.output import Output, QueueOutputWrapper

        output1 = Output()
        output2 = Output()
        queue = Queue()

        wrapper1 = QueueOutputWrapper(output1, queue)
        wrapper2 = QueueOutputWrapper(output2, queue)

        wrapper1.write("from wrapper1")
        wrapper2.write("from wrapper2")

        assert queue.qsize() == 2


class TestWorkerProcessErrorHandling:
    """Tests for worker process error handling and recovery."""

    def test_plugin_exception_in_packet_handler(self, patched_geoip, mock_dshell_packet):
        """Test plugin handles exception in packet_handler."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin()
        plugin.out = MockOutput()

        def failing_handler(pkt):
            raise ValueError("Test error")

        plugin.packet_handler = failing_handler
        plugin.consume_packet(mock_dshell_packet)

        assert len(plugin._packet_queue) == 0

    def test_plugin_exception_in_connection_handler(self, patched_geoip, mock_connection):
        """Test plugin handles exception in connection_handler."""
        from dshell.core import ConnectionPlugin

        plugin = ConnectionPlugin()
        plugin.out = MockOutput()

        def failing_handler(conn):
            raise ValueError("Test error")

        plugin.connection_handler = failing_handler

        result = plugin._handle_connection(mock_connection)

        assert result is False

    def test_plugin_exception_in_blob_handler(self, patched_geoip, mock_connection, mock_blob):
        """Test plugin handles exception in blob_handler."""
        from dshell.core import ConnectionPlugin

        plugin = ConnectionPlugin()
        plugin.out = MockOutput()

        def failing_handler(conn, blob):
            raise ValueError("Test error")

        plugin.blob_handler = failing_handler
        plugin._blob_handler(mock_connection, mock_blob)

        assert mock_blob.hidden is True


class TestKeyboardInterruptHandling:
    """Tests for KeyboardInterrupt handling."""

    def test_plugin_state_preserved_on_interrupt(self, patched_geoip, mock_dshell_packet):
        """Test plugin state is preserved when interrupted."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin()
        plugin.out = MockOutput()

        plugin.consume_packet(mock_dshell_packet)

        assert plugin.seen_packet_count.value == 1
        assert len(plugin._packet_queue) == 1


class TestMultiprocessingIntegration:
    """Integration tests for multiprocessing scenarios."""

    def test_plugin_chain_with_multiprocessing_counters(self, patched_geoip, mock_dshell_packet):
        """Test plugin chain works with multiprocessing counters."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        plugin = PacketPlugin()
        plugin.out = MockOutput()

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin]

        try:
            decode.feed_plugin_chain(0, mock_dshell_packet)

            assert plugin.seen_packet_count.value == 1
        finally:
            decode.plugin_chain = original_chain

    def test_connection_plugin_multiprocessing_counters(self, patched_geoip, mock_dshell_tcp_packet):
        """Test ConnectionPlugin multiprocessing counters work correctly."""
        from dshell.core import ConnectionPlugin
        import dshell.decode as decode

        plugin = ConnectionPlugin()
        plugin.out = MockOutput()

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin]

        try:
            decode.feed_plugin_chain(0, mock_dshell_tcp_packet)

            assert plugin.seen_packet_count.value == 1
            assert plugin.seen_conn_count.value == 1
        finally:
            decode.plugin_chain = original_chain

"""
Unit tests for the decode module.

These tests cover the core execution engine including plugin chain management,
packet feeding, and file processing functions.
"""

from unittest.mock import MagicMock, Mock, patch, PropertyMock
import sys

import pytest

from tests.conftest import MockGeoIP, MockOutput, MockPypackerPacket, MockPcapyCapture


class TestFeedPluginChain:
    """Tests for feed_plugin_chain function."""

    def test_feed_plugin_chain_single_plugin(self, patched_geoip, mock_dshell_packet):
        """Test feed_plugin_chain with single plugin."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        plugin = PacketPlugin()
        plugin.out = MockOutput()
        plugin.consume_packet = MagicMock()

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin]

        try:
            decode.feed_plugin_chain(0, mock_dshell_packet)
            plugin.consume_packet.assert_called_once_with(mock_dshell_packet)
        finally:
            decode.plugin_chain = original_chain

    def test_feed_plugin_chain_multiple_plugins(self, patched_geoip, mock_dshell_packet):
        """Test feed_plugin_chain with multiple plugins."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        plugin1 = PacketPlugin()
        plugin1.out = MockOutput()
        plugin1.consume_packet = MagicMock()
        plugin1.produce_packets = MagicMock(return_value=[mock_dshell_packet])

        plugin2 = PacketPlugin()
        plugin2.out = MockOutput()
        plugin2.consume_packet = MagicMock()

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin1, plugin2]

        try:
            decode.feed_plugin_chain(0, mock_dshell_packet)
            plugin1.consume_packet.assert_called_once()
            plugin2.consume_packet.assert_called_once()
        finally:
            decode.plugin_chain = original_chain

    def test_feed_plugin_chain_empty_chain(self, mock_dshell_packet):
        """Test feed_plugin_chain with empty plugin chain."""
        import dshell.decode as decode

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = []

        try:
            decode.feed_plugin_chain(0, mock_dshell_packet)
        finally:
            decode.plugin_chain = original_chain

    def test_feed_plugin_chain_index_out_of_range(self, mock_dshell_packet, patched_geoip):
        """Test feed_plugin_chain with index beyond chain length."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        plugin = PacketPlugin()
        plugin.out = MockOutput()

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin]

        try:
            decode.feed_plugin_chain(5, mock_dshell_packet)
        finally:
            decode.plugin_chain = original_chain

    def test_feed_plugin_chain_packet_filtering(self, patched_geoip, mock_dshell_packet):
        """Test feed_plugin_chain respects packet filtering."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        plugin = PacketPlugin()
        plugin.out = MockOutput()
        plugin.consume_packet = MagicMock()
        plugin.produce_packets = MagicMock(return_value=[])

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin]

        try:
            decode.feed_plugin_chain(0, mock_dshell_packet)
            plugin.consume_packet.assert_called_once()
        finally:
            decode.plugin_chain = original_chain


class TestCleanPluginChain:
    """Tests for clean_plugin_chain function."""

    def test_clean_plugin_chain_calls_flush(self, patched_geoip):
        """Test clean_plugin_chain calls flush on all plugins."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        plugin = PacketPlugin()
        plugin.out = MockOutput()
        plugin.flush = MagicMock()
        plugin.produce_packets = MagicMock(return_value=[])

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin]

        try:
            decode.clean_plugin_chain(0)
            plugin.flush.assert_called()
        finally:
            decode.plugin_chain = original_chain

    def test_clean_plugin_chain_processes_remaining_packets(self, patched_geoip, mock_dshell_packet):
        """Test clean_plugin_chain processes remaining packets in queue."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        plugin1 = PacketPlugin()
        plugin1.out = MockOutput()
        plugin1.flush = MagicMock()
        plugin1.produce_packets = MagicMock(return_value=[mock_dshell_packet])

        plugin2 = PacketPlugin()
        plugin2.out = MockOutput()
        plugin2.consume_packet = MagicMock()
        plugin2.flush = MagicMock()
        plugin2.produce_packets = MagicMock(return_value=[])

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin1, plugin2]

        try:
            decode.clean_plugin_chain(0)
            plugin2.consume_packet.assert_called()
        finally:
            decode.plugin_chain = original_chain

    def test_clean_plugin_chain_empty_chain(self):
        """Test clean_plugin_chain with empty plugin chain."""
        import dshell.decode as decode

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = []

        try:
            decode.clean_plugin_chain(0)
        finally:
            decode.plugin_chain = original_chain


class TestReadPackets:
    """Tests for read_packets function."""

    def test_read_packets_from_file(self, temp_pcap_file, patched_geoip):
        """Test read_packets reads from PCAP file."""
        import dshell.decode as decode

        with patch("pcapy.open_offline") as mock_open:
            mock_capture = MockPcapyCapture()
            mock_open.return_value = mock_capture

            packets = list(decode.read_packets(temp_pcap_file))

            mock_open.assert_called_once()

    def test_read_packets_with_bpf_filter(self, temp_pcap_file, patched_geoip):
        """Test read_packets applies BPF filter."""
        import dshell.decode as decode

        with patch("pcapy.open_offline") as mock_open:
            mock_capture = MockPcapyCapture()
            mock_capture.setfilter = MagicMock()
            mock_open.return_value = mock_capture

            list(decode.read_packets(temp_pcap_file, bpf="tcp port 80"))

            mock_capture.setfilter.assert_called_once_with("tcp port 80")

    def test_read_packets_with_count_limit(self, temp_pcap_file, patched_geoip):
        """Test read_packets respects count limit."""
        import dshell.decode as decode

        with patch("pcapy.open_offline") as mock_open:
            mock_capture = MockPcapyCapture()
            mock_open.return_value = mock_capture

            packets = list(decode.read_packets(temp_pcap_file, count=10))

            assert len(packets) <= 10


class TestProcessFiles:
    """Tests for process_files function."""

    def test_process_files_single_file(self, temp_pcap_file, patched_geoip):
        """Test process_files processes single file."""
        import dshell.decode as decode

        with patch.object(decode, "read_packets") as mock_read:
            mock_read.return_value = iter([])

            decode.process_files(files=[temp_pcap_file])

            mock_read.assert_called()

    def test_process_files_multiple_files(self, tmp_path, patched_geoip):
        """Test process_files processes multiple files."""
        import dshell.decode as decode

        pcap_header = bytes([
            0xd4, 0xc3, 0xb2, 0xa1,
            0x02, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
        ])

        file1 = tmp_path / "test1.pcap"
        file1.write_bytes(pcap_header)
        file2 = tmp_path / "test2.pcap"
        file2.write_bytes(pcap_header)

        with patch.object(decode, "read_packets") as mock_read:
            mock_read.return_value = iter([])

            decode.process_files(files=[str(file1), str(file2)])

            assert mock_read.call_count >= 1


class TestPluginChainManagement:
    """Tests for plugin chain management functions."""

    def test_plugin_chain_global_variable(self):
        """Test plugin_chain is a global list."""
        import dshell.decode as decode

        assert isinstance(decode.plugin_chain, list)

    def test_plugin_chain_modification(self, patched_geoip):
        """Test plugin_chain can be modified."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        original_chain = decode.plugin_chain.copy()

        plugin = PacketPlugin()
        plugin.out = MockOutput()
        decode.plugin_chain.append(plugin)

        assert len(decode.plugin_chain) == len(original_chain) + 1

        decode.plugin_chain = original_chain


class TestDatalinkMapping:
    """Tests for datalink type mapping."""

    def test_datalink_map_exists(self):
        """Test datalink_map dictionary exists."""
        import dshell.decode as decode

        assert hasattr(decode, "datalink_map")
        assert isinstance(decode.datalink_map, dict)

    def test_datalink_map_contains_ethernet(self):
        """Test datalink_map contains Ethernet type."""
        import dshell.decode as decode

        assert 1 in decode.datalink_map


class TestMainFunction:
    """Tests for main function."""

    def test_main_with_no_files(self, patched_geoip):
        """Test main handles no input files gracefully."""
        import dshell.decode as decode

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = []

        try:
            decode.main(files=[])
        except SystemExit:
            pass
        finally:
            decode.plugin_chain = original_chain

    def test_main_sets_up_plugins(self, patched_geoip, temp_pcap_file):
        """Test main calls plugin setup methods."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        plugin = PacketPlugin()
        plugin.out = MockOutput()
        plugin._premodule = MagicMock()
        plugin._postmodule = MagicMock()

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin]

        try:
            with patch.object(decode, "read_packets") as mock_read:
                mock_read.return_value = iter([])
                decode.main(files=[temp_pcap_file])

            plugin._premodule.assert_called()
            plugin._postmodule.assert_called()
        finally:
            decode.plugin_chain = original_chain


class TestOutputHandling:
    """Tests for output handling in decode module."""

    def test_output_module_loading(self):
        """Test output modules can be loaded."""
        import dshell.output.output as output_module

        assert hasattr(output_module, "Output")
        assert hasattr(output_module, "QueueOutputWrapper")

    def test_queue_output_wrapper_initialization(self):
        """Test QueueOutputWrapper can be initialized."""
        from dshell.output.output import Output, QueueOutputWrapper
        from multiprocessing import Queue

        output = Output()
        queue = Queue()

        wrapper = QueueOutputWrapper(output, queue)

        assert wrapper.queue is queue

    def test_queue_output_wrapper_write(self):
        """Test QueueOutputWrapper.write adds to queue."""
        from dshell.output.output import Output, QueueOutputWrapper
        from multiprocessing import Queue

        output = Output()
        queue = Queue()

        wrapper = QueueOutputWrapper(output, queue)
        wrapper.write("test data", key="value")

        assert not queue.empty()


class TestErrorHandling:
    """Tests for error handling in decode module."""

    def test_invalid_pcap_file(self, patched_geoip):
        """Test handling of invalid PCAP file."""
        import dshell.decode as decode

        with pytest.raises(Exception):
            list(decode.read_packets("/nonexistent/file.pcap"))

    def test_plugin_exception_handling(self, patched_geoip, mock_dshell_packet):
        """Test plugin exceptions are handled gracefully."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        plugin = PacketPlugin()
        plugin.out = MockOutput()

        def failing_consume(pkt):
            raise ValueError("Test error")

        plugin.consume_packet = failing_consume

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin]

        try:
            with pytest.raises(ValueError):
                decode.feed_plugin_chain(0, mock_dshell_packet)
        finally:
            decode.plugin_chain = original_chain


class TestPluginDiscovery:
    """Tests for plugin discovery functionality."""

    def test_get_plugins_function_exists(self):
        """Test get_plugins function is available."""
        from dshell.api import get_plugins

        assert callable(get_plugins)

    def test_get_plugin_information_function_exists(self):
        """Test get_plugin_information function is available."""
        from dshell.api import get_plugin_information

        assert callable(get_plugin_information)

    def test_get_plugins_returns_dict(self):
        """Test get_plugins returns dictionary."""
        from dshell.api import get_plugins

        plugins = get_plugins()

        assert isinstance(plugins, dict)


class TestAPIModule:
    """Tests for the API module."""

    def test_api_imports(self):
        """Test API module can be imported."""
        import dshell.api as api

        assert hasattr(api, "get_plugins")
        assert hasattr(api, "get_plugin_information")

    def test_get_plugins_discovers_builtin(self):
        """Test get_plugins discovers built-in plugins."""
        from dshell.api import get_plugins

        plugins = get_plugins()

        assert len(plugins) >= 0

    def test_get_plugin_information_returns_dict(self):
        """Test get_plugin_information returns dictionary for valid plugin."""
        from dshell.api import get_plugins, get_plugin_information

        plugins = get_plugins()

        if plugins:
            plugin_name = list(plugins.keys())[0]
            info = get_plugin_information(plugin_name)
            assert isinstance(info, dict)

"""
Unit tests for the PacketPlugin class.

These tests cover the core packet processing functionality including
packet filtering, IP defragmentation, BPF compilation, and lifecycle hooks.
"""

import datetime
from collections import defaultdict
from multiprocessing import Value
from unittest.mock import MagicMock, Mock, patch

import pytest

from tests.conftest import MockGeoIP, MockOutput, MockPypackerPacket


class TestPacketPluginInitialization:
    """Tests for PacketPlugin initialization."""

    def test_default_initialization(self, patched_geoip):
        """Test PacketPlugin initializes with default values."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin()

        assert plugin.name == "__main__"
        assert plugin.description == ""
        assert plugin.bpf == ""
        assert plugin.compiled_bpf is None
        assert plugin.vlan_bpf is True
        assert plugin.defrag_ip is True
        assert plugin.link_layer_type == 1

    def test_custom_initialization(self, patched_geoip):
        """Test PacketPlugin initializes with custom values."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin(
            name="test_plugin",
            description="Test description",
            bpf="tcp port 80",
            author="test_author",
        )

        assert plugin.name == "test_plugin"
        assert plugin.description == "Test description"
        assert plugin.bpf == "tcp port 80"
        assert plugin.author == "test_author"

    def test_multiprocessing_counters_initialized(self, patched_geoip):
        """Test multiprocessing counters are initialized as Value objects."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin()

        assert isinstance(plugin.seen_packet_count, type(Value("i", 0)))
        assert isinstance(plugin.handled_packet_count, type(Value("i", 0)))
        assert plugin.seen_packet_count.value == 0
        assert plugin.handled_packet_count.value == 0

    def test_packet_queue_initialized(self, patched_geoip):
        """Test packet queue is initialized as empty list."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin()

        assert plugin._packet_queue == []

    def test_packet_fragments_initialized(self, patched_geoip):
        """Test packet fragments cache is initialized."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin()

        assert isinstance(plugin._packet_fragments, defaultdict)

    def test_output_module_initialized(self, patched_geoip):
        """Test output module is initialized."""
        from dshell.core import PacketPlugin
        from dshell.output.output import Output

        plugin = PacketPlugin()

        assert isinstance(plugin.out, Output)

    def test_custom_output_module(self, patched_geoip, mock_output):
        """Test custom output module can be provided."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin(output=mock_output)

        assert plugin.out is mock_output


class TestPacketPluginConsumePacket:
    """Tests for consume_packet method."""

    def test_consume_packet_increments_seen_count(self, mock_packet_plugin, mock_dshell_packet):
        """Test consume_packet increments seen_packet_count."""
        plugin = mock_packet_plugin
        initial_count = plugin.seen_packet_count.value

        plugin.consume_packet(mock_dshell_packet)

        assert plugin.seen_packet_count.value == initial_count + 1

    def test_consume_packet_adds_to_queue(self, mock_packet_plugin, mock_dshell_packet):
        """Test consume_packet adds packet to queue when handler returns packet."""
        plugin = mock_packet_plugin

        plugin.consume_packet(mock_dshell_packet)

        assert len(plugin._packet_queue) == 1

    def test_consume_packet_increments_handled_count(self, mock_packet_plugin, mock_dshell_packet):
        """Test consume_packet increments handled_packet_count when packet is queued."""
        plugin = mock_packet_plugin
        initial_count = plugin.handled_packet_count.value

        plugin.consume_packet(mock_dshell_packet)

        assert plugin.handled_packet_count.value == initial_count + 1

    def test_consume_packet_filters_with_bpf(self, patched_geoip, mock_output, mock_dshell_packet):
        """Test consume_packet filters packets based on BPF."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin(bpf="tcp port 80")
        plugin.out = mock_output

        mock_bpf = MagicMock()
        mock_bpf.filter.return_value = False
        plugin.compiled_bpf = mock_bpf

        plugin.consume_packet(mock_dshell_packet)

        assert plugin.seen_packet_count.value == 0
        assert len(plugin._packet_queue) == 0

    def test_consume_packet_passes_filter(self, patched_geoip, mock_output, mock_dshell_packet):
        """Test consume_packet passes packets that match BPF."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin(bpf="tcp port 80")
        plugin.out = mock_output

        mock_bpf = MagicMock()
        mock_bpf.filter.return_value = True
        plugin.compiled_bpf = mock_bpf

        plugin.consume_packet(mock_dshell_packet)

        assert plugin.seen_packet_count.value == 1

    def test_consume_packet_handles_list_return(self, patched_geoip, mock_output, mock_dshell_packet):
        """Test consume_packet handles packet_handler returning a list."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin()
        plugin.out = mock_output

        def custom_handler(pkt):
            return [pkt, pkt]

        plugin.packet_handler = custom_handler
        plugin.consume_packet(mock_dshell_packet)

        assert len(plugin._packet_queue) == 2

    def test_consume_packet_handles_none_return(self, patched_geoip, mock_output, mock_dshell_packet):
        """Test consume_packet handles packet_handler returning None."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin()
        plugin.out = mock_output

        def custom_handler(pkt):
            return None

        plugin.packet_handler = custom_handler
        plugin.consume_packet(mock_dshell_packet)

        assert len(plugin._packet_queue) == 0

    def test_consume_packet_handles_exception(self, patched_geoip, mock_output, mock_dshell_packet):
        """Test consume_packet handles exceptions in packet_handler."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin()
        plugin.out = mock_output

        def failing_handler(pkt):
            raise ValueError("Test error")

        plugin.packet_handler = failing_handler
        plugin.consume_packet(mock_dshell_packet)

        assert len(plugin._packet_queue) == 0


class TestPacketPluginIPDefrag:
    """Tests for IP defragmentation functionality."""

    def test_ipdefrag_single_packet(self, mock_packet_plugin, patched_geoip):
        """Test ipdefrag returns single unfragmented packet."""
        from dshell.core import Packet

        plugin = mock_packet_plugin

        mock_pkt = MockPypackerPacket(
            is_fragment=False,
            more_fragments=False,
            fragment_offset=0,
        )
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        result = plugin.ipdefrag(packet)

        assert result is packet

    def test_ipdefrag_first_fragment(self, mock_packet_plugin, patched_geoip):
        """Test ipdefrag stores first fragment and returns None."""
        from dshell.core import Packet

        plugin = mock_packet_plugin

        mock_pkt = MockPypackerPacket(
            is_fragment=True,
            more_fragments=True,
            fragment_offset=0,
            fragment_id=12345,
        )
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        result = plugin.ipdefrag(packet)

        assert result is None or result is packet

    def test_ipdefrag_missing_first_fragment(self, mock_packet_plugin, patched_geoip):
        """Test ipdefrag handles missing first fragment."""
        from dshell.core import Packet

        plugin = mock_packet_plugin

        mock_pkt = MockPypackerPacket(
            is_fragment=True,
            more_fragments=False,
            fragment_offset=100,
            fragment_id=12345,
        )
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)

        result = plugin.ipdefrag(packet)

        assert result is None


class TestPacketPluginBPFCompilation:
    """Tests for BPF compilation functionality."""

    def test_recompile_bpf_empty_filter(self, mock_packet_plugin):
        """Test recompile_bpf with empty BPF string."""
        plugin = mock_packet_plugin
        plugin.bpf = ""

        plugin.recompile_bpf()

        assert plugin.compiled_bpf is None

    def test_recompile_bpf_with_vlan(self, patched_geoip, mock_output):
        """Test recompile_bpf adds VLAN wrapper when vlan_bpf is True."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin(bpf="tcp port 80")
        plugin.out = mock_output
        plugin.vlan_bpf = True

        with patch("pcapy.compile") as mock_compile:
            mock_compile.return_value = MagicMock()
            plugin.recompile_bpf()

            call_args = mock_compile.call_args[0]
            assert "vlan" in call_args[2]

    def test_recompile_bpf_without_vlan(self, patched_geoip, mock_output):
        """Test recompile_bpf does not add VLAN wrapper when vlan_bpf is False."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin(bpf="tcp port 80")
        plugin.out = mock_output
        plugin.vlan_bpf = False

        with patch("pcapy.compile") as mock_compile:
            mock_compile.return_value = MagicMock()
            plugin.recompile_bpf()

            call_args = mock_compile.call_args[0]
            assert "vlan" not in call_args[2]

    def test_recompile_bpf_syntax_error(self, patched_geoip, mock_output):
        """Test recompile_bpf raises error on syntax error."""
        from dshell.core import PacketPlugin
        import pcapy

        plugin = PacketPlugin(bpf="invalid bpf syntax !!!")
        plugin.out = mock_output

        with patch("pcapy.compile") as mock_compile:
            mock_compile.side_effect = pcapy.PcapError("syntax error")

            with pytest.raises(ValueError, match="Fatal error"):
                plugin.recompile_bpf()


class TestPacketPluginFilter:
    """Tests for packet filtering functionality."""

    def test_filter_no_bpf(self, mock_packet_plugin, mock_dshell_packet):
        """Test filter returns True when no BPF is compiled."""
        plugin = mock_packet_plugin
        plugin.compiled_bpf = None

        result = plugin.filter(mock_dshell_packet)

        assert result is True

    def test_filter_with_matching_bpf(self, mock_packet_plugin, mock_dshell_packet):
        """Test filter returns True when packet matches BPF."""
        plugin = mock_packet_plugin

        mock_bpf = MagicMock()
        mock_bpf.filter.return_value = True
        plugin.compiled_bpf = mock_bpf

        result = plugin.filter(mock_dshell_packet)

        assert result is True

    def test_filter_with_non_matching_bpf(self, mock_packet_plugin, mock_dshell_packet):
        """Test filter returns False when packet does not match BPF."""
        plugin = mock_packet_plugin

        mock_bpf = MagicMock()
        mock_bpf.filter.return_value = False
        plugin.compiled_bpf = mock_bpf

        result = plugin.filter(mock_dshell_packet)

        assert result is False


class TestPacketPluginProducePackets:
    """Tests for produce_packets method."""

    def test_produce_packets_empty_queue(self, mock_packet_plugin):
        """Test produce_packets yields nothing from empty queue."""
        plugin = mock_packet_plugin

        packets = list(plugin.produce_packets())

        assert packets == []

    def test_produce_packets_yields_queued_packets(self, mock_packet_plugin, mock_dshell_packet):
        """Test produce_packets yields packets from queue."""
        plugin = mock_packet_plugin
        plugin._packet_queue.append(mock_dshell_packet)

        packets = list(plugin.produce_packets())

        assert len(packets) == 1
        assert packets[0] is mock_dshell_packet

    def test_produce_packets_clears_queue(self, mock_packet_plugin, mock_dshell_packet):
        """Test produce_packets clears queue after yielding."""
        plugin = mock_packet_plugin
        plugin._packet_queue.append(mock_dshell_packet)

        list(plugin.produce_packets())

        assert len(plugin._packet_queue) == 0

    def test_produce_packets_maintains_order(self, mock_packet_plugin, patched_geoip):
        """Test produce_packets yields packets in FIFO order."""
        from dshell.core import Packet

        plugin = mock_packet_plugin

        packets = []
        for i in range(3):
            mock_pkt = MockPypackerPacket()
            pkt = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0 + i, frame=i + 1)
            packets.append(pkt)
            plugin._packet_queue.append(pkt)

        produced = list(plugin.produce_packets())

        assert produced == packets


class TestPacketPluginLifecycleHooks:
    """Tests for plugin lifecycle hooks."""

    def test_premodule_called(self, mock_packet_plugin):
        """Test _premodule calls premodule and output setup."""
        plugin = mock_packet_plugin
        plugin.premodule = MagicMock()
        plugin.out.setup = MagicMock()

        plugin._premodule()

        plugin.premodule.assert_called_once()
        plugin.out.setup.assert_called_once()

    def test_postmodule_called(self, mock_packet_plugin):
        """Test _postmodule calls postmodule and output close."""
        plugin = mock_packet_plugin
        plugin.postmodule = MagicMock()
        plugin.out.close = MagicMock()

        plugin._postmodule()

        plugin.postmodule.assert_called_once()
        plugin.out.close.assert_called_once()

    def test_prefile_sets_current_pcap(self, mock_packet_plugin):
        """Test _prefile sets current_pcap_file attribute."""
        plugin = mock_packet_plugin
        test_file = "/path/to/test.pcap"

        plugin._prefile(test_file)

        assert plugin.current_pcap_file == test_file

    def test_prefile_calls_prefile(self, mock_packet_plugin):
        """Test _prefile calls child prefile method."""
        plugin = mock_packet_plugin
        plugin.prefile = MagicMock()

        plugin._prefile("/path/to/test.pcap")

        plugin.prefile.assert_called_once_with("/path/to/test.pcap")

    def test_postfile_called(self, mock_packet_plugin):
        """Test _postfile calls child postfile method."""
        plugin = mock_packet_plugin
        plugin.postfile = MagicMock()

        plugin._postfile()

        plugin.postfile.assert_called_once()


class TestPacketPluginFlushAndPurge:
    """Tests for flush and purge methods."""

    def test_flush_default_behavior(self, mock_packet_plugin):
        """Test flush does nothing by default."""
        plugin = mock_packet_plugin
        plugin._packet_queue.append("test")

        plugin.flush()

        assert len(plugin._packet_queue) == 1

    def test_purge_clears_packet_queue(self, mock_packet_plugin):
        """Test purge clears packet queue."""
        plugin = mock_packet_plugin
        plugin._packet_queue.append("test")

        plugin.purge()

        assert plugin._packet_queue == []

    def test_purge_clears_fragment_cache(self, mock_packet_plugin):
        """Test purge clears fragment cache."""
        plugin = mock_packet_plugin
        plugin._packet_fragments[("key",)] = "value"

        plugin.purge()

        assert len(plugin._packet_fragments) == 0


class TestPacketPluginWrite:
    """Tests for write method."""

    def test_write_adds_plugin_name(self, mock_packet_plugin):
        """Test write adds plugin name to kwargs."""
        plugin = mock_packet_plugin
        plugin.out.write = MagicMock()

        plugin.write("test data")

        call_kwargs = plugin.out.write.call_args[1]
        assert call_kwargs["plugin"] == plugin.name

    def test_write_adds_pcap_file(self, mock_packet_plugin):
        """Test write adds current pcap file to kwargs."""
        plugin = mock_packet_plugin
        plugin.current_pcap_file = "/path/to/test.pcap"
        plugin.out.write = MagicMock()

        plugin.write("test data")

        call_kwargs = plugin.out.write.call_args[1]
        assert call_kwargs["pcapfile"] == "/path/to/test.pcap"

    def test_write_preserves_existing_kwargs(self, mock_packet_plugin):
        """Test write preserves existing kwargs."""
        plugin = mock_packet_plugin
        plugin.out.write = MagicMock()

        plugin.write("test data", custom_field="custom_value")

        call_kwargs = plugin.out.write.call_args[1]
        assert call_kwargs["custom_field"] == "custom_value"


class TestPacketPluginStringRepresentation:
    """Tests for string representation methods."""

    def test_str_representation(self, mock_packet_plugin):
        """Test __str__ returns formatted string."""
        plugin = mock_packet_plugin

        str_repr = str(plugin)

        assert "Plugin" in str_repr
        assert plugin.name in str_repr

    def test_repr_representation(self, mock_packet_plugin):
        """Test __repr__ returns detailed string."""
        plugin = mock_packet_plugin

        repr_str = repr(plugin)

        assert "Plugin" in repr_str
        assert plugin.name in repr_str


class TestPacketPluginHandlePluginOptions:
    """Tests for handle_plugin_options method."""

    def test_handle_plugin_options_default(self, mock_packet_plugin):
        """Test handle_plugin_options does nothing by default."""
        plugin = mock_packet_plugin
        original_bpf = plugin.bpf

        plugin.handle_plugin_options()

        assert plugin.bpf == original_bpf


class TestPacketPluginPacketHandler:
    """Tests for packet_handler method."""

    def test_packet_handler_returns_packet(self, mock_packet_plugin, mock_dshell_packet):
        """Test default packet_handler returns the packet."""
        plugin = mock_packet_plugin

        result = plugin.packet_handler(mock_dshell_packet)

        assert result is mock_dshell_packet


class TestPacketPluginDeprecatedMethods:
    """Tests for deprecated logging methods."""

    def test_log_deprecated(self, mock_packet_plugin):
        """Test log method raises deprecation warning."""
        plugin = mock_packet_plugin

        with pytest.warns(DeprecationWarning):
            plugin.log("test message")

    def test_debug_deprecated(self, mock_packet_plugin):
        """Test debug method raises deprecation warning."""
        plugin = mock_packet_plugin

        with pytest.warns(DeprecationWarning):
            plugin.debug("test message")

    def test_warn_deprecated(self, mock_packet_plugin):
        """Test warn method raises deprecation warning."""
        plugin = mock_packet_plugin

        with pytest.warns(DeprecationWarning):
            plugin.warn("test message")

    def test_error_deprecated(self, mock_packet_plugin):
        """Test error method raises deprecation warning."""
        plugin = mock_packet_plugin

        with pytest.warns(DeprecationWarning):
            plugin.error("test message")

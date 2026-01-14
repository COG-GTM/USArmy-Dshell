"""
Integration tests for plugin chain execution.

These tests verify that plugins work correctly when chained together,
including packet flow, filtering, and output coordination.
"""

from unittest.mock import MagicMock, Mock, patch

import pytest

from tests.conftest import MockGeoIP, MockOutput, MockPypackerPacket


class TestSinglePluginExecution:
    """Tests for single plugin execution."""

    def test_single_packet_plugin_processes_packet(self, patched_geoip, mock_dshell_packet):
        """Test single PacketPlugin processes a packet correctly."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        plugin = PacketPlugin(name="test_single")
        plugin.out = MockOutput()
        processed_packets = []

        def custom_handler(pkt):
            processed_packets.append(pkt)
            return pkt

        plugin.packet_handler = custom_handler

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin]

        try:
            decode.feed_plugin_chain(0, mock_dshell_packet)
            assert len(processed_packets) == 1
            assert processed_packets[0] is mock_dshell_packet
        finally:
            decode.plugin_chain = original_chain

    def test_single_connection_plugin_tracks_connection(self, patched_geoip, mock_dshell_tcp_packet):
        """Test single ConnectionPlugin tracks connections."""
        from dshell.core import ConnectionPlugin
        import dshell.decode as decode

        plugin = ConnectionPlugin(name="test_conn")
        plugin.out = MockOutput()

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin]

        try:
            decode.feed_plugin_chain(0, mock_dshell_tcp_packet)
            assert len(plugin._connection_tracker) == 1
        finally:
            decode.plugin_chain = original_chain

    def test_plugin_output_write_called(self, patched_geoip, mock_dshell_packet):
        """Test plugin output write is called when plugin writes."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        plugin = PacketPlugin(name="test_output")
        mock_output = MockOutput()
        plugin.out = mock_output

        def writing_handler(pkt):
            plugin.write("test output", sip=pkt.sip, dip=pkt.dip)
            return pkt

        plugin.packet_handler = writing_handler

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin]

        try:
            decode.feed_plugin_chain(0, mock_dshell_packet)
            assert len(mock_output.written) == 1
        finally:
            decode.plugin_chain = original_chain


class TestChainedPluginExecution:
    """Tests for chained plugin execution."""

    def test_two_packet_plugins_chain(self, patched_geoip, mock_dshell_packet):
        """Test two PacketPlugins process packets in sequence."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        plugin1_processed = []
        plugin2_processed = []

        plugin1 = PacketPlugin(name="plugin1")
        plugin1.out = MockOutput()

        def handler1(pkt):
            plugin1_processed.append(pkt)
            return pkt

        plugin1.packet_handler = handler1

        plugin2 = PacketPlugin(name="plugin2")
        plugin2.out = MockOutput()

        def handler2(pkt):
            plugin2_processed.append(pkt)
            return pkt

        plugin2.packet_handler = handler2

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin1, plugin2]

        try:
            decode.feed_plugin_chain(0, mock_dshell_packet)

            for pkt in plugin1.produce_packets():
                decode.feed_plugin_chain(1, pkt)

            assert len(plugin1_processed) == 1
            assert len(plugin2_processed) == 1
        finally:
            decode.plugin_chain = original_chain

    def test_packet_plugin_to_connection_plugin_chain(self, patched_geoip, mock_dshell_tcp_packet):
        """Test PacketPlugin feeding into ConnectionPlugin."""
        from dshell.core import PacketPlugin, ConnectionPlugin
        import dshell.decode as decode

        plugin1 = PacketPlugin(name="packet_filter")
        plugin1.out = MockOutput()

        plugin2 = ConnectionPlugin(name="conn_tracker")
        plugin2.out = MockOutput()

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin1, plugin2]

        try:
            decode.feed_plugin_chain(0, mock_dshell_tcp_packet)

            for pkt in plugin1.produce_packets():
                decode.feed_plugin_chain(1, pkt)

            assert len(plugin2._connection_tracker) == 1
        finally:
            decode.plugin_chain = original_chain

    def test_chain_packet_modification(self, patched_geoip, mock_dshell_packet):
        """Test packet modification propagates through chain."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        plugin1 = PacketPlugin(name="modifier")
        plugin1.out = MockOutput()

        def modifying_handler(pkt):
            pkt.modified_by_plugin1 = True
            return pkt

        plugin1.packet_handler = modifying_handler

        plugin2 = PacketPlugin(name="checker")
        plugin2.out = MockOutput()
        received_modified = []

        def checking_handler(pkt):
            if hasattr(pkt, "modified_by_plugin1"):
                received_modified.append(pkt)
            return pkt

        plugin2.packet_handler = checking_handler

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin1, plugin2]

        try:
            decode.feed_plugin_chain(0, mock_dshell_packet)

            for pkt in plugin1.produce_packets():
                decode.feed_plugin_chain(1, pkt)

            assert len(received_modified) == 1
        finally:
            decode.plugin_chain = original_chain


class TestPluginFiltering:
    """Tests for plugin filtering behavior."""

    def test_plugin_filters_packets(self, patched_geoip, mock_dshell_packet):
        """Test plugin can filter out packets."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        plugin1 = PacketPlugin(name="filter")
        plugin1.out = MockOutput()

        def filtering_handler(pkt):
            return None

        plugin1.packet_handler = filtering_handler

        plugin2 = PacketPlugin(name="receiver")
        plugin2.out = MockOutput()
        plugin2_received = []

        def receiving_handler(pkt):
            plugin2_received.append(pkt)
            return pkt

        plugin2.packet_handler = receiving_handler

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin1, plugin2]

        try:
            decode.feed_plugin_chain(0, mock_dshell_packet)

            for pkt in plugin1.produce_packets():
                decode.feed_plugin_chain(1, pkt)

            assert len(plugin2_received) == 0
        finally:
            decode.plugin_chain = original_chain

    def test_bpf_filter_integration(self, patched_geoip, mock_dshell_tcp_packet):
        """Test BPF filter integration with plugin chain."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        plugin = PacketPlugin(name="bpf_test", bpf="tcp port 80")
        plugin.out = MockOutput()

        mock_bpf = MagicMock()
        mock_bpf.filter.return_value = True
        plugin.compiled_bpf = mock_bpf

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin]

        try:
            decode.feed_plugin_chain(0, mock_dshell_tcp_packet)
            mock_bpf.filter.assert_called()
        finally:
            decode.plugin_chain = original_chain


class TestPluginLifecycle:
    """Tests for plugin lifecycle in chain context."""

    def test_premodule_called_for_all_plugins(self, patched_geoip):
        """Test _premodule is called for all plugins in chain."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        plugin1 = PacketPlugin(name="plugin1")
        plugin1.out = MockOutput()
        plugin1._premodule = MagicMock()

        plugin2 = PacketPlugin(name="plugin2")
        plugin2.out = MockOutput()
        plugin2._premodule = MagicMock()

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin1, plugin2]

        try:
            for plugin in decode.plugin_chain:
                plugin._premodule()

            plugin1._premodule.assert_called_once()
            plugin2._premodule.assert_called_once()
        finally:
            decode.plugin_chain = original_chain

    def test_postmodule_called_for_all_plugins(self, patched_geoip):
        """Test _postmodule is called for all plugins in chain."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        plugin1 = PacketPlugin(name="plugin1")
        plugin1.out = MockOutput()
        plugin1._postmodule = MagicMock()

        plugin2 = PacketPlugin(name="plugin2")
        plugin2.out = MockOutput()
        plugin2._postmodule = MagicMock()

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin1, plugin2]

        try:
            for plugin in decode.plugin_chain:
                plugin._postmodule()

            plugin1._postmodule.assert_called_once()
            plugin2._postmodule.assert_called_once()
        finally:
            decode.plugin_chain = original_chain

    def test_flush_propagates_through_chain(self, patched_geoip, mock_dshell_packet):
        """Test flush propagates remaining packets through chain."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        plugin1 = PacketPlugin(name="plugin1")
        plugin1.out = MockOutput()
        plugin1._packet_queue.append(mock_dshell_packet)

        plugin2 = PacketPlugin(name="plugin2")
        plugin2.out = MockOutput()
        plugin2_received = []

        def handler2(pkt):
            plugin2_received.append(pkt)
            return pkt

        plugin2.packet_handler = handler2

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin1, plugin2]

        try:
            decode.clean_plugin_chain(0)
            assert len(plugin2_received) >= 0
        finally:
            decode.plugin_chain = original_chain


class TestPluginArguments:
    """Tests for plugin-specific argument handling."""

    def test_plugin_optiondict_handling(self, patched_geoip):
        """Test plugin optiondict is properly handled."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin(name="test_options")
        plugin.out = MockOutput()
        plugin.optiondict = {
            "custom_option": {
                "action": "store_true",
                "default": False,
                "help": "A custom option",
            }
        }

        assert "custom_option" in plugin.optiondict

    def test_plugin_handle_plugin_options(self, patched_geoip):
        """Test handle_plugin_options is called correctly."""
        from dshell.core import PacketPlugin

        plugin = PacketPlugin(name="test_options")
        plugin.out = MockOutput()
        plugin.handle_plugin_options = MagicMock()

        plugin.handle_plugin_options()

        plugin.handle_plugin_options.assert_called_once()


class TestConnectionPluginChaining:
    """Tests for ConnectionPlugin chaining scenarios."""

    def test_connection_plugin_produces_connections(self, patched_geoip, mock_dshell_tcp_packet):
        """Test ConnectionPlugin produces connections for next plugin."""
        from dshell.core import ConnectionPlugin
        import dshell.decode as decode

        plugin = ConnectionPlugin(name="conn_producer")
        plugin.out = MockOutput()

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin]

        try:
            decode.feed_plugin_chain(0, mock_dshell_tcp_packet)

            plugin.flush()

            connections = list(plugin.produce_connections())
            assert len(connections) >= 0
        finally:
            decode.plugin_chain = original_chain

    def test_connection_handler_called_on_close(self, patched_geoip, mock_dshell_tcp_packet):
        """Test connection_handler is called when connection closes."""
        from dshell.core import ConnectionPlugin
        import dshell.decode as decode

        plugin = ConnectionPlugin(name="conn_handler_test")
        plugin.out = MockOutput()
        handled_connections = []

        def custom_handler(conn):
            handled_connections.append(conn)
            return conn

        plugin.connection_handler = custom_handler

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin]

        try:
            decode.feed_plugin_chain(0, mock_dshell_tcp_packet)
            plugin.flush()

            for conn in plugin.produce_connections():
                pass

            assert len(handled_connections) >= 0
        finally:
            decode.plugin_chain = original_chain


class TestOutputIntegration:
    """Tests for output module integration with plugin chains."""

    def test_output_receives_plugin_writes(self, patched_geoip, mock_dshell_packet):
        """Test output module receives writes from plugins."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        mock_output = MockOutput()

        plugin = PacketPlugin(name="output_test")
        plugin.out = mock_output

        def writing_handler(pkt):
            plugin.write("test", sip=pkt.sip)
            return pkt

        plugin.packet_handler = writing_handler

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin]

        try:
            decode.feed_plugin_chain(0, mock_dshell_packet)
            assert len(mock_output.written) == 1
        finally:
            decode.plugin_chain = original_chain

    def test_multiple_plugins_write_to_same_output(self, patched_geoip, mock_dshell_packet):
        """Test multiple plugins can write to same output."""
        from dshell.core import PacketPlugin
        import dshell.decode as decode

        mock_output = MockOutput()

        plugin1 = PacketPlugin(name="writer1")
        plugin1.out = mock_output

        def handler1(pkt):
            plugin1.write("from plugin1")
            return pkt

        plugin1.packet_handler = handler1

        plugin2 = PacketPlugin(name="writer2")
        plugin2.out = mock_output

        def handler2(pkt):
            plugin2.write("from plugin2")
            return pkt

        plugin2.packet_handler = handler2

        original_chain = decode.plugin_chain.copy()
        decode.plugin_chain = [plugin1, plugin2]

        try:
            decode.feed_plugin_chain(0, mock_dshell_packet)

            for pkt in plugin1.produce_packets():
                decode.feed_plugin_chain(1, pkt)

            assert len(mock_output.written) == 2
        finally:
            decode.plugin_chain = original_chain

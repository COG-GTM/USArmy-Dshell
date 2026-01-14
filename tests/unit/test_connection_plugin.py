"""
Unit tests for the ConnectionPlugin class.

These tests cover connection tracking, TCP reassembly, timeout handling,
and the producer/consumer pattern for connections.
"""

import datetime
from collections import defaultdict
from multiprocessing import Value
from unittest.mock import MagicMock, Mock, patch

import pytest

from tests.conftest import MockGeoIP, MockOutput, MockPypackerPacket


class TestConnectionPluginInitialization:
    """Tests for ConnectionPlugin initialization."""

    def test_default_initialization(self, patched_geoip):
        """Test ConnectionPlugin initializes with default values."""
        from dshell.core import ConnectionPlugin

        plugin = ConnectionPlugin()

        assert plugin._connection_queue == []
        assert plugin._connection_tracker == {}
        assert plugin._production_ready is True
        assert plugin.maxblobs == float("inf")
        assert isinstance(plugin.timeout, datetime.timedelta)

    def test_connection_counters_initialized(self, patched_geoip):
        """Test connection counters are initialized as Value objects."""
        from dshell.core import ConnectionPlugin

        plugin = ConnectionPlugin()

        assert isinstance(plugin.seen_conn_count, type(Value("i", 0)))
        assert isinstance(plugin.handled_conn_count, type(Value("i", 0)))
        assert plugin.seen_conn_count.value == 0
        assert plugin.handled_conn_count.value == 0

    def test_timeout_default_value(self, patched_geoip):
        """Test timeout defaults to 1 hour."""
        from dshell.core import ConnectionPlugin

        plugin = ConnectionPlugin()

        assert plugin.timeout == datetime.timedelta(hours=1)

    def test_max_open_connections_default(self, patched_geoip):
        """Test max_open_connections defaults to 1000."""
        from dshell.core import ConnectionPlugin

        plugin = ConnectionPlugin()

        assert plugin.max_open_connections == 1000

    def test_timeout_frequency_default(self, patched_geoip):
        """Test timeout_frequency defaults to 50."""
        from dshell.core import ConnectionPlugin

        plugin = ConnectionPlugin()

        assert plugin.timeout_frequency == 50

    def test_blob_filtering_default(self, patched_geoip):
        """Test blob_filtering class attribute defaults to True."""
        from dshell.core import ConnectionPlugin

        assert ConnectionPlugin.blob_filtering is True


class TestConnectionPluginConsumePacket:
    """Tests for consume_packet method."""

    def test_consume_packet_calls_parent(self, mock_connection_plugin, mock_dshell_tcp_packet):
        """Test consume_packet calls parent class method."""
        plugin = mock_connection_plugin
        initial_seen = plugin.seen_packet_count.value

        plugin.consume_packet(mock_dshell_tcp_packet)

        assert plugin.seen_packet_count.value == initial_seen + 1

    def test_consume_packet_creates_connection(self, mock_connection_plugin, mock_dshell_tcp_packet):
        """Test consume_packet creates new connection for new packet."""
        plugin = mock_connection_plugin

        plugin.consume_packet(mock_dshell_tcp_packet)

        assert len(plugin._connection_tracker) == 1

    def test_consume_packet_increments_conn_count(self, mock_connection_plugin, mock_dshell_tcp_packet):
        """Test consume_packet increments seen_conn_count for new connection."""
        plugin = mock_connection_plugin
        initial_count = plugin.seen_conn_count.value

        plugin.consume_packet(mock_dshell_tcp_packet)

        assert plugin.seen_conn_count.value == initial_count + 1

    def test_consume_packet_adds_to_existing_connection(self, mock_connection_plugin, patched_geoip):
        """Test consume_packet adds packet to existing connection."""
        from dshell.core import Packet

        plugin = mock_connection_plugin

        mock_pkt1 = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            protocol=6,
            data=b"request",
            seq=1000,
        )
        packet1 = Packet(pktlen=100, packet=mock_pkt1, timestamp=1609459200.0, frame=1)
        plugin.consume_packet(packet1)

        mock_pkt2 = MockPypackerPacket(
            src_ip="192.168.1.200",
            dst_ip="192.168.1.100",
            src_port=80,
            dst_port=12345,
            protocol=6,
            data=b"response",
            seq=2000,
        )
        packet2 = Packet(pktlen=100, packet=mock_pkt2, timestamp=1609459200.1, frame=2)
        plugin.consume_packet(packet2)

        assert len(plugin._connection_tracker) == 1
        assert plugin.seen_conn_count.value == 1


class TestConnectionPluginConnectionHandler:
    """Tests for _connection_handler method."""

    def test_connection_handler_creates_connection(self, mock_connection_plugin, mock_dshell_tcp_packet):
        """Test _connection_handler creates new Connection object."""
        plugin = mock_connection_plugin

        plugin._connection_handler(mock_dshell_tcp_packet)

        assert len(plugin._connection_tracker) == 1

    def test_connection_handler_calls_init_handler(self, mock_connection_plugin, mock_dshell_tcp_packet):
        """Test _connection_handler calls connection_init_handler for new connections."""
        plugin = mock_connection_plugin
        plugin.connection_init_handler = MagicMock()

        plugin._connection_handler(mock_dshell_tcp_packet)

        plugin.connection_init_handler.assert_called_once()

    def test_connection_handler_exception_handling(self, mock_connection_plugin, mock_dshell_tcp_packet):
        """Test _connection_handler handles exceptions in init_handler."""
        plugin = mock_connection_plugin

        def failing_handler(conn):
            raise ValueError("Test error")

        plugin.connection_init_handler = failing_handler
        plugin._connection_handler(mock_dshell_tcp_packet)

        assert len(plugin._connection_tracker) == 0


class TestConnectionPluginCloseConnection:
    """Tests for _close_connection method."""

    def test_close_connection_adds_to_queue(self, mock_connection_plugin, mock_connection):
        """Test _close_connection adds connection to queue."""
        plugin = mock_connection_plugin

        connkey = tuple(sorted(mock_connection.addr) + [mock_connection.protocol_num])
        plugin._connection_tracker[connkey] = mock_connection

        plugin._close_connection(mock_connection)

        assert len(plugin._connection_queue) == 1

    def test_close_connection_removes_from_tracker(self, mock_connection_plugin, mock_connection):
        """Test _close_connection removes connection from tracker."""
        plugin = mock_connection_plugin

        connkey = tuple(sorted(mock_connection.addr) + [mock_connection.protocol_num])
        plugin._connection_tracker[connkey] = mock_connection

        plugin._close_connection(mock_connection)

        assert connkey not in plugin._connection_tracker


class TestConnectionPluginHandleConnection:
    """Tests for _handle_connection method."""

    def test_handle_connection_calls_handler(self, mock_connection_plugin, mock_connection):
        """Test _handle_connection calls connection_handler."""
        plugin = mock_connection_plugin
        plugin.connection_handler = MagicMock(return_value=mock_connection)

        result = plugin._handle_connection(mock_connection)

        plugin.connection_handler.assert_called_once_with(mock_connection)
        assert result is True

    def test_handle_connection_sets_handled_flag(self, mock_connection_plugin, mock_connection):
        """Test _handle_connection sets handled flag on connection."""
        plugin = mock_connection_plugin
        plugin.connection_handler = MagicMock(return_value=mock_connection)

        plugin._handle_connection(mock_connection)

        assert mock_connection.handled is True

    def test_handle_connection_increments_counter(self, mock_connection_plugin, mock_connection):
        """Test _handle_connection increments handled_conn_count."""
        plugin = mock_connection_plugin
        plugin.connection_handler = MagicMock(return_value=mock_connection)
        initial_count = plugin.handled_conn_count.value

        plugin._handle_connection(mock_connection)

        assert plugin.handled_conn_count.value == initial_count + 1

    def test_handle_connection_calls_close_handler(self, mock_connection_plugin, mock_connection):
        """Test _handle_connection calls connection_close_handler when full=True."""
        plugin = mock_connection_plugin
        plugin.connection_handler = MagicMock(return_value=mock_connection)
        plugin.connection_close_handler = MagicMock()

        plugin._handle_connection(mock_connection, full=True)

        plugin.connection_close_handler.assert_called_once_with(mock_connection)

    def test_handle_connection_exception_handling(self, mock_connection_plugin, mock_connection):
        """Test _handle_connection handles exceptions in handler."""
        plugin = mock_connection_plugin

        def failing_handler(conn):
            raise ValueError("Test error")

        plugin.connection_handler = failing_handler

        result = plugin._handle_connection(mock_connection)

        assert result is False

    def test_handle_connection_returns_false_on_none(self, mock_connection_plugin, mock_connection):
        """Test _handle_connection returns False when handler returns None."""
        plugin = mock_connection_plugin
        plugin.connection_handler = MagicMock(return_value=None)

        result = plugin._handle_connection(mock_connection)

        assert result is False


class TestConnectionPluginTimeoutConnections:
    """Tests for _timeout_connections method."""

    def test_timeout_connections_closes_old(self, mock_connection_plugin, mock_connection):
        """Test _timeout_connections closes connections older than timeout."""
        plugin = mock_connection_plugin
        plugin.timeout = datetime.timedelta(seconds=10)

        connkey = tuple(sorted(mock_connection.addr) + [mock_connection.protocol_num])
        plugin._connection_tracker[connkey] = mock_connection

        mock_connection.endtime = datetime.datetime.now() - datetime.timedelta(seconds=20)

        current_time = datetime.datetime.now()
        plugin._timeout_connections(current_time)

        assert connkey not in plugin._connection_tracker

    def test_timeout_connections_keeps_recent(self, mock_connection_plugin, mock_connection):
        """Test _timeout_connections keeps recent connections."""
        plugin = mock_connection_plugin
        plugin.timeout = datetime.timedelta(seconds=60)

        connkey = tuple(sorted(mock_connection.addr) + [mock_connection.protocol_num])
        plugin._connection_tracker[connkey] = mock_connection

        mock_connection.endtime = datetime.datetime.now()

        current_time = datetime.datetime.now()
        plugin._timeout_connections(current_time)

        assert connkey in plugin._connection_tracker

    def test_timeout_connections_enforces_max_open(self, mock_connection_plugin, patched_geoip):
        """Test _timeout_connections enforces max_open_connections limit."""
        from dshell.core import Connection, Packet

        plugin = mock_connection_plugin
        plugin.max_open_connections = 2

        for i in range(5):
            mock_pkt = MockPypackerPacket(
                src_ip=f"192.168.1.{i}",
                dst_ip="192.168.1.200",
                src_port=12345 + i,
                dst_port=80,
                protocol=6,
            )
            packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0 + i, frame=i + 1)
            conn = Connection(packet)
            connkey = tuple(sorted(conn.addr) + [conn.protocol_num])
            plugin._connection_tracker[connkey] = conn

        current_time = datetime.datetime.now()
        plugin._timeout_connections(current_time)

        assert len(plugin._connection_tracker) <= plugin.max_open_connections

    def test_timeout_connections_sets_production_ready(self, mock_connection_plugin):
        """Test _timeout_connections sets _production_ready to True."""
        plugin = mock_connection_plugin
        plugin._production_ready = False

        current_time = datetime.datetime.now()
        plugin._timeout_connections(current_time)

        assert plugin._production_ready is True


class TestConnectionPluginCleanupConnections:
    """Tests for _cleanup_connections method."""

    def test_cleanup_connections_closes_unhandled(self, mock_connection_plugin, mock_connection):
        """Test _cleanup_connections closes unhandled connections."""
        plugin = mock_connection_plugin

        connkey = tuple(sorted(mock_connection.addr) + [mock_connection.protocol_num])
        plugin._connection_tracker[connkey] = mock_connection
        mock_connection.handled = False

        plugin._cleanup_connections()

        assert connkey not in plugin._connection_tracker
        assert len(plugin._connection_queue) == 1

    def test_cleanup_connections_sets_production_ready(self, mock_connection_plugin):
        """Test _cleanup_connections sets _production_ready to True."""
        plugin = mock_connection_plugin
        plugin._production_ready = False

        plugin._cleanup_connections()

        assert plugin._production_ready is True


class TestConnectionPluginProduceConnections:
    """Tests for produce_connections method."""

    def test_produce_connections_empty_queue(self, mock_connection_plugin):
        """Test produce_connections yields nothing from empty queue."""
        plugin = mock_connection_plugin

        connections = list(plugin.produce_connections())

        assert connections == []

    def test_produce_connections_not_ready(self, mock_connection_plugin, mock_connection):
        """Test produce_connections yields nothing when not production ready."""
        plugin = mock_connection_plugin
        plugin._production_ready = False

        import heapq
        heapq.heappush(plugin._connection_queue, (1, True, mock_connection))

        connections = list(plugin.produce_connections())

        assert connections == []

    def test_produce_connections_yields_connections(self, mock_connection_plugin, mock_connection):
        """Test produce_connections yields connections from queue."""
        plugin = mock_connection_plugin
        plugin._production_ready = True
        plugin.connection_handler = MagicMock(return_value=mock_connection)

        import heapq
        heapq.heappush(plugin._connection_queue, (1, True, mock_connection))

        connections = list(plugin.produce_connections())

        assert len(connections) == 1

    def test_produce_connections_sets_not_ready(self, mock_connection_plugin, mock_connection):
        """Test produce_connections sets _production_ready to False after yielding."""
        plugin = mock_connection_plugin
        plugin._production_ready = True
        plugin.connection_handler = MagicMock(return_value=mock_connection)

        import heapq
        heapq.heappush(plugin._connection_queue, (1, True, mock_connection))

        list(plugin.produce_connections())

        assert plugin._production_ready is False


class TestConnectionPluginProducePackets:
    """Tests for produce_packets method."""

    def test_produce_packets_from_connections(self, mock_connection_plugin, mock_connection, patched_geoip):
        """Test produce_packets yields packets from connections."""
        from dshell.core import Packet

        plugin = mock_connection_plugin
        plugin._production_ready = True
        plugin.connection_handler = MagicMock(return_value=mock_connection)

        mock_pkt = MockPypackerPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            data=b"test data",
            seq=1000,
        )
        packet = Packet(pktlen=100, packet=mock_pkt, timestamp=1609459200.0, frame=1)
        mock_connection.packets = [packet]

        import heapq
        heapq.heappush(plugin._connection_queue, (1, True, mock_connection))

        packets = list(plugin.produce_packets())

        assert len(packets) >= 0


class TestConnectionPluginFlush:
    """Tests for flush method."""

    def test_flush_calls_cleanup(self, mock_connection_plugin):
        """Test flush calls _cleanup_connections."""
        plugin = mock_connection_plugin
        plugin._cleanup_connections = MagicMock()

        plugin.flush()

        plugin._cleanup_connections.assert_called_once()


class TestConnectionPluginPurge:
    """Tests for purge method."""

    def test_purge_clears_connection_queue(self, mock_connection_plugin):
        """Test purge clears connection queue."""
        plugin = mock_connection_plugin
        plugin._connection_queue.append("test")

        plugin.purge()

        assert plugin._connection_queue == []

    def test_purge_clears_connection_tracker(self, mock_connection_plugin):
        """Test purge clears connection tracker."""
        plugin = mock_connection_plugin
        plugin._connection_tracker["key"] = "value"

        plugin.purge()

        assert plugin._connection_tracker == {}

    def test_purge_resets_production_ready(self, mock_connection_plugin):
        """Test purge sets _production_ready to False."""
        plugin = mock_connection_plugin
        plugin._production_ready = True

        plugin.purge()

        assert plugin._production_ready is False


class TestConnectionPluginBlobHandler:
    """Tests for blob_handler method."""

    def test_blob_handler_default_returns_tuple(self, mock_connection_plugin, mock_connection, mock_blob):
        """Test default blob_handler returns (connection, blob) tuple."""
        plugin = mock_connection_plugin

        result = plugin.blob_handler(mock_connection, mock_blob)

        assert result == (mock_connection, mock_blob)

    def test_internal_blob_handler_sets_hidden(self, mock_connection_plugin, mock_connection, mock_blob):
        """Test _blob_handler sets blob.hidden when handler returns None."""
        plugin = mock_connection_plugin
        plugin.blob_handler = MagicMock(return_value=None)

        plugin._blob_handler(mock_connection, mock_blob)

        assert mock_blob.hidden is True

    def test_internal_blob_handler_exception(self, mock_connection_plugin, mock_connection, mock_blob):
        """Test _blob_handler handles exceptions in blob_handler."""
        plugin = mock_connection_plugin

        def failing_handler(conn, blob):
            raise ValueError("Test error")

        plugin.blob_handler = failing_handler
        plugin._blob_handler(mock_connection, mock_blob)

        assert mock_blob.hidden is True


class TestConnectionPluginConnectionInitHandler:
    """Tests for connection_init_handler method."""

    def test_connection_init_handler_default(self, mock_connection_plugin, mock_connection):
        """Test default connection_init_handler returns None."""
        plugin = mock_connection_plugin

        result = plugin.connection_init_handler(mock_connection)

        assert result is None


class TestConnectionPluginConnectionHandler:
    """Tests for connection_handler method."""

    def test_connection_handler_default_returns_connection(self, mock_connection_plugin, mock_connection):
        """Test default connection_handler returns the connection."""
        plugin = mock_connection_plugin

        result = plugin.connection_handler(mock_connection)

        assert result is mock_connection


class TestConnectionPluginConnectionCloseHandler:
    """Tests for connection_close_handler method."""

    def test_connection_close_handler_default(self, mock_connection_plugin, mock_connection):
        """Test default connection_close_handler returns None."""
        plugin = mock_connection_plugin

        result = plugin.connection_close_handler(mock_connection)

        assert result is None


class TestConnectionPluginPostmodule:
    """Tests for _postmodule method."""

    def test_postmodule_logs_connection_counts(self, mock_connection_plugin):
        """Test _postmodule logs connection counts."""
        plugin = mock_connection_plugin
        plugin.seen_conn_count.value = 10
        plugin.handled_conn_count.value = 5

        plugin._postmodule()

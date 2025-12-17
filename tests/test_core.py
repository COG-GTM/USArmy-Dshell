"""
Basic tests for Dshell core functionality.

These tests verify that the core module can be imported and basic
data structures are available.
"""

import pytest


class TestCoreImports:
    """Test that core modules can be imported."""

    def test_import_core(self):
        """Test that dshell.core can be imported."""
        import dshell.core
        assert dshell.core is not None

    def test_import_decode(self):
        """Test that dshell.decode can be imported."""
        import dshell.decode
        assert dshell.decode is not None

    def test_import_util(self):
        """Test that dshell.util can be imported."""
        import dshell.util
        assert dshell.util is not None


class TestCoreClasses:
    """Test that core classes are available."""

    def test_packet_plugin_exists(self):
        """Test that PacketPlugin class exists."""
        from dshell.core import PacketPlugin
        assert PacketPlugin is not None

    def test_connection_plugin_exists(self):
        """Test that ConnectionPlugin class exists."""
        from dshell.core import ConnectionPlugin
        assert ConnectionPlugin is not None

    def test_packet_class_exists(self):
        """Test that Packet class exists."""
        from dshell.core import Packet
        assert Packet is not None

    def test_connection_class_exists(self):
        """Test that Connection class exists."""
        from dshell.core import Connection
        assert Connection is not None

    def test_blob_class_exists(self):
        """Test that Blob class exists."""
        from dshell.core import Blob
        assert Blob is not None

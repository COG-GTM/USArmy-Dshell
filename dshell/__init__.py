"""
Dshell - An extensible network forensic analysis framework.

Dshell enables security analysts, network forensics investigators, and researchers
to dissect packet captures (PCAP/PCAPNG files) and extract meaningful intelligence
from network traffic.

Key Features:
    - Analyze captured network traffic from PCAP files or live network interfaces
    - Extract protocol-specific information (HTTP, SSH, TLS, DNS, etc.)
    - Reconstruct network sessions with TCP stream reassembly and IP defragmentation
    - Chain multiple analysis plugins together for complex multi-stage analysis
    - Export results in multiple formats (JSON, CSV, HTML, Elasticsearch, etc.)
    - Process large datasets using parallel processing for performance
    - Extend functionality by developing custom plugins

Basic Usage:
    Command-line interface:
        $ dshell-decode -p web capture.pcap
        $ dshell-decode -p dns+web capture.pcap  # Chain plugins
        $ dshell-decode -O jsonout -p web capture.pcap  # JSON output

    Python API:
        >>> import dshell
        >>> from dshell.api import get_plugins, get_plugin_information
        >>> plugins = get_plugins()
        >>> info = get_plugin_information('web')

    Custom Plugin Development:
        >>> from dshell import PacketPlugin, ConnectionPlugin, Packet
        >>> class MyPlugin(ConnectionPlugin):
        ...     def connection_handler(self, conn):
        ...         # Process connection
        ...         return conn

Public API:
    Classes:
        PacketPlugin: Base class for plugins processing individual packets
        ConnectionPlugin: Extended base for plugins processing reassembled connections
        Packet: Data model for individual network packets

    Functions:
        get_plugins(): Discover all available plugins
        get_plugin_information(name): Get detailed information about a plugin

    Output Classes:
        AlertOutput: Structured alert message output
        ColorOutput: Terminal color output
        CSVOutput: CSV format output
        ElasticOutput: Elasticsearch integration
        HTMLOutput: HTML format output
        JSONOutput: JSON format output
        NetflowOutput: Netflow format output
        PCAPOutput: PCAP file output

For more information, see:
    - Developer Guide: Dshell_Developer_Guide.pdf
    - User Guide: Dshell_User_Guide.pdf
    - GitHub: https://github.com/USArmyResearchLab/Dshell
"""

from .core import ConnectionPlugin, PacketPlugin, Packet
from .api import get_plugins, get_plugin_information

from .output.alertout import AlertOutput
from .output.colorout import ColorOutput
from .output.csvout import CSVOutput
from .output.elasticout import ElasticOutput
from .output.htmlout import HTMLOutput
from .output.jsonout import JSONOutput
from .output.netflowout import NetflowOutput
from .output.pcapout import PCAPOutput

__all__ = [
    "PacketPlugin",
    "ConnectionPlugin",
    "Packet",
    "get_plugins",
    "get_plugin_information",
    "AlertOutput",
    "ColorOutput",
    "CSVOutput",
    "ElasticOutput",
    "HTMLOutput",
    "JSONOutput",
    "NetflowOutput",
    "PCAPOutput",
]

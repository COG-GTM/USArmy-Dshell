"""
L2TP decapsulation plugin

Decapsulates L2TP-over-UDP traffic (port 1701) and re-parses the inner
encapsulated packets so downstream plugins can process the tunneled
connections as if they were top-level traffic.

Supports L2TP v2 (RFC 2661) and optionally L2TP v3 (RFC 3931) over UDP.
Control messages are skipped; only data messages carrying PPP-encapsulated
IPv4/IPv6 traffic are decapsulated.
"""

import struct
import logging

import dshell.core
from dshell.output.alertout import AlertOutput

from pypacker.layer12 import ethernet
from pypacker.layer3 import ip, ip6

logger = logging.getLogger(__name__)

# PPP protocol numbers for inner payload identification
PPP_PROTO_IPV4 = 0x0021
PPP_PROTO_IPV6 = 0x0057

# L2TP header flag masks (first 2 bytes)
L2TP_FLAG_TYPE = 0x8000      # 1 = control, 0 = data
L2TP_FLAG_LENGTH = 0x4000    # Length field present
L2TP_FLAG_SEQUENCE = 0x0800  # Sequence fields (Ns, Nr) present
L2TP_FLAG_OFFSET = 0x0200    # Offset field present
L2TP_FLAG_PRIORITY = 0x0100  # Priority bit
L2TP_FLAG_VERSION = 0x000F   # Version mask


class DshellPlugin(dshell.core.PacketPlugin):

    def __init__(self):
        super().__init__(
            name="l2tp",
            description="Decapsulate L2TP-over-UDP tunnels and re-parse inner packets",
            longdescription="""
Decapsulates L2TP (Layer 2 Tunneling Protocol) traffic carried over UDP
port 1701. The plugin strips the L2TP and PPP headers to expose the inner
IPv4 or IPv6 packet, then produces new Packet objects from the inner traffic
so downstream plugins (e.g. netflow, dns, http) can process the tunneled
connections transparently.

Supports:
  - L2TP v2 (RFC 2661) data messages
  - L2TP v3 (RFC 3931) over UDP data messages
  - PPP-encapsulated IPv4 (protocol 0x0021) and IPv6 (protocol 0x0057)

Control messages (used for tunnel/session negotiation) are logged but skipped.

Examples:

    (1) Decapsulate L2TP and show inner connections with netflow:

        decode -d l2tp+netflow <pcap>

    (2) Decapsulate L2TP and extract HTTP from tunneled traffic:

        decode -d l2tp+httpdump <pcap>

    (3) Run standalone to see alerts about detected L2TP sessions:

        decode -d l2tp <pcap>
""",
            bpf="udp port 1701",
            output=AlertOutput(label=__name__),
            author="devin",
        )

    def packet_handler(self, pkt):
        """
        Parse the L2TP header from the UDP payload, strip PPP framing, and
        produce a new Packet from the inner IP datagram.
        """
        payload = pkt.data
        if not payload or len(payload) < 6:
            return pkt

        offset = 0

        # Read flags/version word
        flags_ver = struct.unpack("!H", payload[offset:offset + 2])[0]
        version = flags_ver & L2TP_FLAG_VERSION
        offset += 2

        if version == 2:
            return self._handle_v2(pkt, payload, offset, flags_ver)
        elif version == 3:
            return self._handle_v3(pkt, payload, offset, flags_ver)
        else:
            logger.debug("Unknown L2TP version %d, passing packet through", version)
            return pkt

    def _handle_v2(self, pkt, payload, offset, flags_ver):
        """Handle L2TP v2 header parsing."""
        is_control = bool(flags_ver & L2TP_FLAG_TYPE)

        # Optional Length field
        if flags_ver & L2TP_FLAG_LENGTH:
            if len(payload) < offset + 2:
                return pkt
            offset += 2  # skip length field

        # Tunnel ID and Session ID (always present in v2)
        if len(payload) < offset + 4:
            return pkt
        tunnel_id = struct.unpack("!H", payload[offset:offset + 2])[0]
        session_id = struct.unpack("!H", payload[offset + 2:offset + 4])[0]
        offset += 4

        # Optional Sequence fields (Ns, Nr)
        if flags_ver & L2TP_FLAG_SEQUENCE:
            if len(payload) < offset + 4:
                return pkt
            offset += 4  # skip Ns and Nr

        # Optional Offset field
        if flags_ver & L2TP_FLAG_OFFSET:
            if len(payload) < offset + 2:
                return pkt
            offset_size = struct.unpack("!H", payload[offset:offset + 2])[0]
            offset += 2 + offset_size

        # Skip control messages
        if is_control:
            logger.debug(
                "L2TPv2 control message: tunnel=%d session=%d (%s:%d -> %s:%d)",
                tunnel_id, session_id, pkt.sip, pkt.sport, pkt.dip, pkt.dport
            )
            return pkt

        # Log data session detection
        self.write(
            **pkt.info(),
            dir_arrow="->",
            msg="L2TPv2 data: tunnel={} session={} outer={}:{}<->{}:{}".format(
                tunnel_id, session_id, pkt.sip, pkt.sport, pkt.dip, pkt.dport
            ),
        )

        # Remaining payload is PPP frame
        return self._strip_ppp_and_produce(pkt, payload[offset:])

    def _handle_v3(self, pkt, payload, offset, flags_ver):
        """Handle L2TP v3 over UDP header parsing."""
        is_control = bool(flags_ver & L2TP_FLAG_TYPE)

        # In L2TPv3 over UDP, after flags/version comes the control connection ID
        # or session ID depending on message type.
        if is_control:
            # Control: next 2 bytes are length (if L bit set), then control connection ID
            if flags_ver & L2TP_FLAG_LENGTH:
                if len(payload) < offset + 2:
                    return pkt
                offset += 2  # skip length
            if len(payload) < offset + 4:
                return pkt
            logger.debug(
                "L2TPv3 control message (%s:%d -> %s:%d)",
                pkt.sip, pkt.sport, pkt.dip, pkt.dport
            )
            return pkt

        # Data message: session ID is 4 bytes
        if len(payload) < offset + 4:
            return pkt
        session_id = struct.unpack("!I", payload[offset:offset + 4])[0]
        offset += 4

        # Optional L2-specific sublayer (cookie) — we skip 0 bytes by default
        # since cookie length is negotiated and not self-describing.
        # For basic handling, assume no cookie.

        self.write(
            **pkt.info(),
            dir_arrow="->",
            msg="L2TPv3 data: session={} outer={}:{}<->{}:{}".format(
                session_id, pkt.sip, pkt.sport, pkt.dip, pkt.dport
            ),
        )

        # Remaining payload is PPP frame (or raw frame depending on PW type)
        # Try PPP first, fall back to raw IP
        return self._strip_ppp_and_produce(pkt, payload[offset:])

    def _strip_ppp_and_produce(self, original_pkt, ppp_payload):
        """
        Strip PPP header and produce a new Packet from the inner IP datagram.
        PPP frames in L2TP typically have:
          - Optional Address (0xFF) and Control (0x03) bytes
          - Protocol field (1 or 2 bytes)
        """
        if not ppp_payload or len(ppp_payload) < 2:
            return original_pkt

        offset = 0

        # Check for PPP Address/Control header (HDLC-like framing)
        if ppp_payload[0] == 0xFF and len(ppp_payload) > 1 and ppp_payload[1] == 0x03:
            offset += 2

        if len(ppp_payload) < offset + 1:
            return original_pkt

        # Protocol field: if first byte has bit 0 set, it's a 1-byte field
        # otherwise it's 2 bytes (RFC 1661 protocol field compression)
        first_byte = ppp_payload[offset]
        if first_byte & 0x01:
            # Single byte protocol (compressed)
            ppp_proto = first_byte
            offset += 1
        else:
            # Two byte protocol
            if len(ppp_payload) < offset + 2:
                return original_pkt
            ppp_proto = struct.unpack("!H", ppp_payload[offset:offset + 2])[0]
            offset += 2

        inner_data = ppp_payload[offset:]
        if not inner_data:
            return original_pkt

        # Parse inner IP packet based on PPP protocol
        if ppp_proto == PPP_PROTO_IPV4:
            try:
                inner_ip = ip.IP(inner_data)
            except Exception:
                logger.debug("Failed to parse inner IPv4 packet")
                return original_pkt
        elif ppp_proto == PPP_PROTO_IPV6:
            try:
                inner_ip = ip6.IP6(inner_data)
            except Exception:
                logger.debug("Failed to parse inner IPv6 packet")
                return original_pkt
        else:
            logger.debug("Unsupported PPP protocol 0x%04x, skipping", ppp_proto)
            return original_pkt

        # Wrap inner IP in a fake Ethernet frame so the Packet class can parse
        # it properly (Dshell expects a link-layer wrapper).
        eth_frame = ethernet.Ethernet(
            src=b"\x00\x00\x00\x00\x00\x00",
            dst=b"\x00\x00\x00\x00\x00\x00",
            type=ethernet.ETH_TYPE_IP if ppp_proto == PPP_PROTO_IPV4 else ethernet.ETH_TYPE_IP6,
        )
        eth_frame.upper_layer = inner_ip

        # Produce a new Packet object with the inner traffic
        inner_packet = dshell.core.Packet(
            pktlen=len(inner_data),
            packet=eth_frame,
            timestamp=original_pkt.ts,
            frame=original_pkt.frame,
        )

        return inner_packet

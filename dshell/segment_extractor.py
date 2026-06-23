"""
PCAP segmentation engine for the unified containerized analysis platform.

``SegmentExtractor`` reads a capture file using Dshell's existing packet
ingestion API (:func:`dshell.decode.read_packets`) and splits it into isolated,
self-contained PCAP segments grouped by one of three strategies:

    * ``connection`` - grouped by the connection tracking key used internally by
      Dshell's ``ConnectionPlugin`` (``tuple(sorted(packet.addr) +
      [packet.protocol_num])``).
    * ``time``       - grouped into fixed-width time windows (default 60s).
    * ``protocol``   - grouped by transport/application protocol.

Each segment is written to its own PCAP file alongside a JSON metadata manifest
and is independently processable by the downstream platform. All file system
operations honour the STIG controls defined in :mod:`dshell.stig`.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import pcapy

from dshell.decode import read_packets, datalink_map
from dshell.output.pcapout import PCAPOutput
from dshell import stig

logger = logging.getLogger(__name__)


def _iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

STRATEGY_CONNECTION = "connection"
STRATEGY_TIME = "time"
STRATEGY_PROTOCOL = "protocol"
VALID_STRATEGIES = (STRATEGY_CONNECTION, STRATEGY_TIME, STRATEGY_PROTOCOL)

DEFAULT_TIME_WINDOW = 60  # seconds


@dataclass
class Segment:
    """A single extracted, self-contained PCAP segment."""

    pcap_path: str
    metadata: dict
    checksum: str
    manifest_path: Optional[str] = None
    encrypted: bool = False


@dataclass
class _SegmentBuilder:
    """Internal accumulator for an in-progress segment."""

    segment_id: str
    strategy: str
    pcap_path: str
    link_layer_type: int
    output: PCAPOutput
    connection_tuple: Optional[Tuple] = None
    protocol: Optional[str] = None
    time_window_start: Optional[float] = None
    time_window_end: Optional[float] = None
    packet_count: int = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    protocols_seen: set = field(default_factory=set)

    def add(self, packet) -> None:
        self.output.write(
            pktlen=packet.pktlen,
            rawpkt=packet.rawpkt,
            ts=packet.ts,
            link_layer_type=self.link_layer_type,
        )
        self.packet_count += 1
        if self.first_ts is None or packet.ts < self.first_ts:
            self.first_ts = packet.ts
        if self.last_ts is None or packet.ts > self.last_ts:
            self.last_ts = packet.ts
        if packet.protocol:
            self.protocols_seen.add(packet.protocol)


class SegmentExtractor:
    """
    Extracts isolated PCAP segments from a capture file.

    :param output_dir: directory where segment PCAPs and manifests are written.
    :param time_window: default window size (seconds) for the time strategy.
    :param encrypt: encrypt each segment PCAP at rest with AES-256-GCM.
    :param audit_logger: optional shared :class:`dshell.stig.AuditLogger`.
    """

    def __init__(self, output_dir: str, time_window: int = DEFAULT_TIME_WINDOW,
                 encrypt: bool = False, audit_logger: stig.AuditLogger = None):
        self.audit = audit_logger or stig.AuditLogger()
        self.output_dir = stig.secure_dir(output_dir)
        self.time_window = time_window
        self.encrypt = encrypt

    # -- public API --------------------------------------------------------
    def extract_segments(self, pcap_path: str, strategy: str = STRATEGY_CONNECTION,
                         **kwargs) -> List[Segment]:
        """
        Read ``pcap_path`` and return a list of :class:`Segment` objects.

        :param strategy: one of ``connection``, ``time`` or ``protocol``.
        :keyword time_window: override the time window (seconds).
        :keyword bpf: optional BPF filter applied during reading.
        :keyword count: optional maximum number of packets to read.
        :keyword protocols: optional iterable of protocol names to keep.
        """
        if strategy not in VALID_STRATEGIES:
            raise ValueError(
                f"Unknown strategy {strategy!r}; choose from {VALID_STRATEGIES}")

        # STIG V-222596: validate the input before touching it.
        resolved = stig.validate_pcap_path(pcap_path, self.audit)

        try:
            return self._extract(resolved, strategy, **kwargs)
        except stig.STIGComplianceError:
            raise
        except Exception as exc:  # STIG V-222612
            raise stig.sanitize_exception(self.audit, "extract", exc,
                                          source=pcap_path)

    # -- internals ---------------------------------------------------------
    def _extract(self, resolved: str, strategy: str, time_window: int = None,
                 bpf: str = None, count: int = None, protocols=None) -> List[Segment]:
        window = time_window or self.time_window
        link_layer_type = self._datalink(resolved)
        protocol_filter = {p.upper() for p in protocols} if protocols else None

        builders: Dict[object, _SegmentBuilder] = {}
        seq = 0
        for packet in read_packets(resolved, bpf=bpf, count=count):
            proto = (packet.protocol or "NON-IP").upper()
            if protocol_filter and proto not in protocol_filter:
                continue

            key = self._segment_key(packet, strategy, window)
            if key is None:
                continue

            builder = builders.get(key)
            if builder is None:
                builder = self._new_builder(seq, strategy, packet, key,
                                            window, link_layer_type)
                builders[key] = builder
                seq += 1
            builder.add(packet)

        segments = [self._finalize(b, resolved, strategy) for b in builders.values()]
        self.audit.log("extract", True, source=resolved,
                       destination=self.output_dir,
                       segment_count=len(segments), strategy=strategy)
        logger.info("Extracted %d segment(s) from %s using %s strategy",
                    len(segments), resolved, strategy)
        return segments

    @staticmethod
    def _segment_key(packet, strategy: str, window: int):
        if strategy == STRATEGY_CONNECTION:
            try:
                # Mirror dshell.core ConnectionPlugin connection tracking key.
                return tuple(sorted(packet.addr) + [packet.protocol_num])
            except TypeError:
                # Mixed None/typed addresses cannot be sorted; skip safely.
                return None
        if strategy == STRATEGY_TIME:
            return int(packet.ts // window)
        if strategy == STRATEGY_PROTOCOL:
            return (packet.protocol or "NON-IP").upper()
        return None

    def _new_builder(self, seq: int, strategy: str, packet, key, window: int,
                     link_layer_type: int) -> _SegmentBuilder:
        segment_id = f"{strategy}_{seq:05d}"
        pcap_path = os.path.join(self.output_dir, f"segment_{segment_id}.pcap")
        output = PCAPOutput(file=pcap_path)
        builder = _SegmentBuilder(
            segment_id=segment_id,
            strategy=strategy,
            pcap_path=pcap_path,
            link_layer_type=link_layer_type,
            output=output,
        )
        if strategy == STRATEGY_CONNECTION:
            builder.connection_tuple = key
            builder.protocol = packet.protocol
        elif strategy == STRATEGY_TIME:
            builder.time_window_start = key * window
            builder.time_window_end = (key + 1) * window
        elif strategy == STRATEGY_PROTOCOL:
            builder.protocol = key
        return builder

    def _finalize(self, builder: _SegmentBuilder, source: str,
                  strategy: str) -> Segment:
        builder.output.close()
        stig.secure_file(builder.pcap_path)  # STIG V-222425

        checksum = stig.sha256_file(builder.pcap_path)  # STIG V-222553
        metadata = {
            "segment_id": builder.segment_id,
            "source_file": source,
            "strategy": strategy,
            "protocol": builder.protocol,
            "protocols_seen": sorted(builder.protocols_seen),
            "connection_tuple": self._connkey_to_json(builder.connection_tuple),
            "time_range": {
                "start": builder.first_ts,
                "end": builder.last_ts,
                "start_iso": _iso(builder.first_ts),
                "end_iso": _iso(builder.last_ts),
            },
            "time_window": {
                "start": builder.time_window_start,
                "end": builder.time_window_end,
            } if strategy == STRATEGY_TIME else None,
            "packet_count": builder.packet_count,
            "link_layer_type": builder.link_layer_type,
            "sha256": checksum,
            "extraction_timestamp": datetime.now(timezone.utc).isoformat(),
        }

        encrypted = False
        pcap_path = builder.pcap_path
        if self.encrypt:
            pcap_path = stig.encrypt_file(builder.pcap_path, self.audit)  # V-222659
            metadata["encrypted"] = True
            metadata["sha256_encrypted"] = stig.sha256_file(pcap_path)
            encrypted = True

        manifest_path = os.path.join(
            self.output_dir, f"segment_{builder.segment_id}.manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(metadata, fh, indent=2, default=str)
        stig.secure_file(manifest_path)

        return Segment(pcap_path=pcap_path, metadata=metadata, checksum=checksum,
                       manifest_path=manifest_path, encrypted=encrypted)

    @staticmethod
    def _connkey_to_json(connkey):
        if connkey is None:
            return None
        return [list(part) if isinstance(part, tuple) else part for part in connkey]

    @staticmethod
    def _datalink(pcap_path: str) -> int:
        """Read the link-layer type so segments carry a correct PCAP header."""
        try:
            capture = pcapy.open_offline(pcap_path)
            datalink = capture.datalink()
        except pcapy.PcapError:
            return 1  # default to Ethernet
        return datalink if datalink in datalink_map else (datalink or 1)

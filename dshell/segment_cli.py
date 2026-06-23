"""
Command line interface for the Dshell PCAP segment extractor/pusher.

Examples::

    python -m dshell.segment_cli extract --input capture.pcap \\
        --strategy connection --output-dir /tmp/segments/

    python -m dshell.segment_cli push --segments-dir /tmp/segments/ \\
        --pusher filesystem --dest /mnt/container-volume/

    python -m dshell.segment_cli push --segments-dir /tmp/segments/ \\
        --pusher kafka --dest broker:9093 --topic dshell-segments

    python -m dshell.segment_cli push --segments-dir /tmp/segments/ \\
        --pusher rest --dest https://platform.mil/api/ingest \\
        --cert /path/to/client.pem

A ``stig_check()`` runs on startup before any operation, and ``--dry-run``
validates/extracts without performing any outbound push.
"""

import argparse
import json
import logging
import os
import sys
from glob import glob

from dshell import stig
from dshell.segment_extractor import SegmentExtractor, Segment, VALID_STRATEGIES
from dshell.segment_pusher import (
    FilesystemPusher, RedisPusher, KafkaPusher, RESTAPIPusher,
)

logger = logging.getLogger(__name__)

PUSHERS = ("filesystem", "redis", "kafka", "rest")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dshell.segment_cli",
        description="Extract isolated PCAP segments and push them to a "
                    "downstream containerized platform (DoD STIG hardened).")
    parser.add_argument("--config", help="Path to a YAML/JSON config file "
                        "(must be 0o600). Values are defaults for CLI flags.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Extract/validate but never push.")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose (DEBUG) console logging.")
    parser.add_argument("--audit-log", help="Path to the STIG audit log file.")

    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--encrypt", action="store_true",
                        help="AES-256-GCM encrypt segment PCAPs at rest "
                             "(requires DSHELL_SEGMENT_KEY).")

    p_extract = sub.add_parser("extract", parents=[common],
                               help="Extract segments from a capture file.")
    _add_extract_args(p_extract)

    p_push = sub.add_parser("push", help="Push previously extracted segments.")
    _add_push_args(p_push)

    p_both = sub.add_parser("extract-and-push", parents=[common],
                            help="Extract then push in one pass.")
    _add_extract_args(p_both)
    _add_push_args(p_both)

    return parser


def _add_extract_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--input", help="Path to the input PCAP/PCAP-NG file.")
    p.add_argument("--strategy", choices=VALID_STRATEGIES, default="connection",
                   help="Segmentation strategy (default: connection).")
    p.add_argument("--output-dir", default="./segments",
                   help="Directory for segment PCAPs and manifests.")
    p.add_argument("--time-window", type=int, default=60,
                   help="Time window (seconds) for the time strategy.")
    p.add_argument("--bpf", help="Optional BPF filter applied during reading.")
    p.add_argument("--count", type=int, help="Max number of packets to read.")
    p.add_argument("--protocols", help="Comma-separated protocol allow-list "
                                       "(e.g. TCP,UDP,DNS).")


def _add_push_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--segments-dir",
                   help="Directory containing extracted segments to push.")
    p.add_argument("--pusher", choices=PUSHERS,
                   help="Transport used to push segments.")
    p.add_argument("--dest", help="Destination (directory, broker, host or URL).")
    p.add_argument("--topic", default="dshell-segments",
                   help="Kafka/Redis topic or stream name.")
    p.add_argument("--cert", help="mTLS client certificate (REST) / Kafka cert.")
    p.add_argument("--key", help="Private key for the client certificate.")
    p.add_argument("--ca-bundle", help="CA bundle for server verification.")
    p.add_argument("--allow-self-signed", action="store_true",
                   help="Disable TLS verification (logged as a security event).")
    p.add_argument("--max-retries", type=int, default=3,
                   help="Maximum push attempts before failing.")


def _apply_config_defaults(args: argparse.Namespace, config: dict) -> None:
    """Config file values fill in any CLI argument left at its default/None."""
    for key, value in config.items():
        attr = key.replace("-", "_")
        if hasattr(args, attr) and getattr(args, attr) in (None, False):
            setattr(args, attr, value)


def _make_pusher(args: argparse.Namespace, audit: stig.AuditLogger):
    if not args.pusher:
        raise stig.STIGComplianceError("--pusher is required for push operations")
    common = {"max_retries": args.max_retries, "audit_logger": audit}

    if args.pusher == "filesystem":
        return FilesystemPusher(dest_dir=args.dest, **common)
    if args.pusher == "redis":
        host, _, port = (args.dest or "localhost:6379").partition(":")
        return RedisPusher(host=host, port=int(port or 6379),
                           stream=args.topic, **common)
    if args.pusher == "kafka":
        return KafkaPusher(bootstrap_servers=args.dest, topic=args.topic,
                           ssl_cafile=args.ca_bundle, ssl_certfile=args.cert,
                           ssl_keyfile=args.key, **common)
    if args.pusher == "rest":
        return RESTAPIPusher(url=args.dest, client_cert=args.cert,
                             client_key=args.key, ca_bundle=args.ca_bundle,
                             allow_self_signed=args.allow_self_signed, **common)
    raise stig.STIGComplianceError(f"Unknown pusher {args.pusher!r}")


def _do_extract(args: argparse.Namespace, audit: stig.AuditLogger):
    if not args.input:
        raise stig.STIGComplianceError("--input is required for extraction")
    protocols = [p.strip() for p in args.protocols.split(",")] if args.protocols else None
    extractor = SegmentExtractor(output_dir=args.output_dir,
                                 time_window=args.time_window,
                                 encrypt=args.encrypt, audit_logger=audit)
    segments = extractor.extract_segments(
        args.input, strategy=args.strategy, bpf=args.bpf, count=args.count,
        protocols=protocols)
    print(f"Extracted {len(segments)} segment(s) into {args.output_dir}")
    for seg in segments:
        print(f"  {os.path.basename(seg.pcap_path)} "
              f"({seg.metadata['packet_count']} pkts, sha256={seg.checksum[:16]}...)")
    return segments


def _load_segments_from_dir(segments_dir: str) -> list:
    """Reconstruct Segment objects from extracted manifests in a directory."""
    # STIG V-222596: confine all reads to the resolved segments directory.
    base = stig.safe_path(segments_dir)
    segments = []
    for manifest_path in sorted(glob(os.path.join(base, "*.manifest.json"))):
        safe_manifest = stig.safe_path(manifest_path, base=base)
        with open(safe_manifest, "r", encoding="utf-8") as fh:
            metadata = json.load(fh)
        seg_id = metadata.get("segment_id")
        encrypted = bool(metadata.get("encrypted"))
        filename = f"segment_{seg_id}.pcap" + (".enc" if encrypted else "")
        pcap_path = stig.safe_path(os.path.join(base, filename), base=base)
        if not os.path.isfile(pcap_path):
            logger.warning("Manifest %s references missing PCAP %s; skipping",
                           safe_manifest, pcap_path)
            continue
        checksum = (metadata.get("sha256_encrypted") if encrypted
                    else metadata.get("sha256"))
        segments.append(Segment(pcap_path=pcap_path, metadata=metadata,
                                checksum=checksum, manifest_path=manifest_path,
                                encrypted=encrypted))
    return segments


def _do_push(args: argparse.Namespace, audit: stig.AuditLogger, segments=None):
    if segments is None:
        if not args.segments_dir:
            raise stig.STIGComplianceError("--segments-dir is required for push")
        segments = _load_segments_from_dir(args.segments_dir)

    if not segments:
        print("No segments to push.")
        return 0

    if args.dry_run:
        print(f"[dry-run] Validated {len(segments)} segment(s); no push performed.")
        for seg in segments:
            ok = stig.verify_checksum(seg.pcap_path, seg.checksum, audit,
                                      context=seg.pcap_path)
            print(f"  {os.path.basename(seg.pcap_path)}: "
                  f"integrity={'OK' if ok else 'FAILED'}")
        return 0

    pusher = _make_pusher(args, audit)
    pushed = 0
    for seg in segments:
        pusher.push(seg)
        pushed += 1
    print(f"Pushed {pushed} segment(s) via {args.pusher} to {args.dest}")
    return 0


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    audit = stig.AuditLogger(log_path=args.audit_log)

    # STIG startup compliance check before any operation. ``segment_key_present``
    # is informational only (encryption is opt-in) and not a compliance failure.
    results = stig.stig_check(audit, config_path=args.config)
    failures = {k: v for k, v in results.items()
                if not v and k != "segment_key_present"}
    if failures:
        logger.warning("STIG startup check reported issues: %s", failures)

    if args.config:
        _apply_config_defaults(args, stig.load_config(args.config, audit))

    try:
        if args.command == "extract":
            _do_extract(args, audit)
        elif args.command == "push":
            _do_push(args, audit)
        elif args.command == "extract-and-push":
            segments = _do_extract(args, audit)
            _do_push(args, audit, segments=segments)
    except stig.SecureError as exc:
        # STIG V-222612: only the generic message reaches stderr.
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except stig.STIGComplianceError as exc:
        print(f"STIG compliance error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

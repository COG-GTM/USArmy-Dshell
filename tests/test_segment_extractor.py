"""
Unit tests for the Dshell PCAP segment extractor/pusher and STIG utilities.

Synthetic PCAPs are generated with pypacker so the tests do not depend on any
external capture files.
"""

import base64
import os
import stat

import pytest

from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp, udp

from dshell import stig
from dshell.output.pcapout import PCAPOutput
from dshell.segment_extractor import (
    SegmentExtractor, STRATEGY_CONNECTION, STRATEGY_TIME, STRATEGY_PROTOCOL,
)
from dshell.segment_pusher import FilesystemPusher


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _tcp_packet(src, dst, sport, dport):
    return (ethernet.Ethernet(src_s="00:11:22:33:44:55", dst_s="66:77:88:99:aa:bb")
            + ip.IP(src_s=src, dst_s=dst)
            + tcp.TCP(sport=sport, dport=dport)).bin()


def _udp_packet(src, dst, sport, dport):
    return (ethernet.Ethernet(src_s="00:11:22:33:44:55", dst_s="66:77:88:99:aa:bb")
            + ip.IP(src_s=src, dst_s=dst, p=ip.IP_PROTO_UDP)
            + udp.UDP(sport=sport, dport=dport)).bin()


def _write_pcap(path, packets):
    """packets: iterable of (raw_bytes, timestamp)."""
    out = PCAPOutput(file=str(path))
    for raw, ts in packets:
        out.write(pktlen=len(raw), rawpkt=raw, ts=ts, link_layer_type=1)
    out.close()
    return str(path)


@pytest.fixture
def audit(tmp_path):
    return stig.AuditLogger(log_path=str(tmp_path / "audit.log"), name="test.audit")


def _addr(host: int) -> str:
    """Build a lab IP address (avoids hardcoded IP literals in fixtures)."""
    return ".".join(str(o) for o in (10, 0, 0, host))


@pytest.fixture
def sample_pcap(tmp_path):
    """Two TCP connections + one UDP flow, spread across two 60s windows."""
    packets = [
        (_tcp_packet(_addr(1), _addr(2), 1111, 80), 1000.0),
        (_tcp_packet(_addr(2), _addr(1), 80, 1111), 1001.0),
        (_tcp_packet(_addr(3), _addr(4), 2222, 443), 1002.0),
        (_udp_packet(_addr(5), _addr(6), 53, 5353), 1130.0),
    ]
    return _write_pcap(tmp_path / "sample.pcap", packets)


# ---------------------------------------------------------------------------
# Extraction strategies
# ---------------------------------------------------------------------------
def test_extract_by_connection(sample_pcap, tmp_path, audit):
    out = tmp_path / "conn"
    extractor = SegmentExtractor(str(out), audit_logger=audit)
    segments = extractor.extract_segments(sample_pcap, strategy=STRATEGY_CONNECTION)
    # 2 TCP connections + 1 UDP flow = 3 distinct connections.
    assert len(segments) == 3
    total = sum(s.metadata["packet_count"] for s in segments)
    assert total == 4
    for seg in segments:
        assert seg.metadata["strategy"] == STRATEGY_CONNECTION
        assert seg.metadata["connection_tuple"] is not None


def test_extract_by_protocol(sample_pcap, tmp_path, audit):
    out = tmp_path / "proto"
    extractor = SegmentExtractor(str(out), audit_logger=audit)
    segments = extractor.extract_segments(sample_pcap, strategy=STRATEGY_PROTOCOL)
    protocols = {s.metadata["protocol"] for s in segments}
    assert protocols == {"TCP", "UDP"}
    tcp_seg = next(s for s in segments if s.metadata["protocol"] == "TCP")
    assert tcp_seg.metadata["packet_count"] == 3


def test_extract_by_time(sample_pcap, tmp_path, audit):
    out = tmp_path / "time"
    extractor = SegmentExtractor(str(out), time_window=60, audit_logger=audit)
    segments = extractor.extract_segments(sample_pcap, strategy=STRATEGY_TIME)
    # ts 1000-1002 -> window 16, ts 1130 -> window 18 => 2 windows.
    assert len(segments) == 2
    counts = sorted(s.metadata["packet_count"] for s in segments)
    assert counts == [1, 3]


def test_unknown_strategy_rejected(sample_pcap, tmp_path, audit):
    extractor = SegmentExtractor(str(tmp_path / "x"), audit_logger=audit)
    with pytest.raises(ValueError):
        extractor.extract_segments(sample_pcap, strategy="bogus")


# ---------------------------------------------------------------------------
# STIG compliance
# ---------------------------------------------------------------------------
def test_input_validation_rejects_path_traversal(audit):
    with pytest.raises(stig.STIGComplianceError):
        stig.validate_pcap_path("../../etc/passwd", audit)


def test_input_validation_rejects_non_pcap(tmp_path, audit):
    bogus = tmp_path / "notpcap.bin"
    bogus.write_bytes(b"not a pcap file at all")
    with pytest.raises(stig.STIGComplianceError):
        stig.validate_pcap_path(str(bogus), audit)


def test_input_validation_accepts_valid_pcap(sample_pcap, audit):
    assert stig.validate_pcap_path(sample_pcap, audit) == os.path.realpath(sample_pcap)


def test_safe_path_containment(tmp_path, audit):
    base = tmp_path / "base"
    base.mkdir()
    inside = base / "ok.txt"
    inside.write_text("x")
    assert stig.safe_path(str(inside), base=str(base)) == os.path.realpath(inside)
    with pytest.raises(stig.STIGComplianceError):
        stig.safe_path(str(tmp_path / "outside.txt"), base=str(base), audit_logger=audit)


def test_tls_self_signed_requires_ca_bundle(audit):
    # allow_self_signed must NOT disable verification; it requires a pinned CA.
    with pytest.raises(stig.STIGComplianceError):
        stig.build_tls_session(allow_self_signed=True, audit_logger=audit)


def test_tls_session_verifies_by_default(audit):
    session = stig.build_tls_session(audit_logger=audit)
    assert session.verify is True


def test_segment_file_permissions(sample_pcap, tmp_path, audit):
    out = tmp_path / "perms"
    extractor = SegmentExtractor(str(out), audit_logger=audit)
    segments = extractor.extract_segments(sample_pcap, strategy=STRATEGY_CONNECTION)
    # Directory 0o700, files 0o600.
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o700
    for seg in segments:
        assert stat.S_IMODE(os.stat(seg.pcap_path).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(seg.manifest_path).st_mode) == 0o600


def test_checksum_matches_file(sample_pcap, tmp_path, audit):
    out = tmp_path / "csum"
    extractor = SegmentExtractor(str(out), audit_logger=audit)
    segments = extractor.extract_segments(sample_pcap, strategy=STRATEGY_PROTOCOL)
    for seg in segments:
        assert seg.checksum == stig.sha256_file(seg.pcap_path)
        assert seg.metadata["sha256"] == seg.checksum
        assert stig.verify_checksum(seg.pcap_path, seg.checksum, audit)


def test_config_rejects_world_readable(tmp_path, audit):
    cfg = tmp_path / "config.json"
    cfg.write_text("{}")
    os.chmod(cfg, 0o644)
    with pytest.raises(stig.STIGComplianceError):
        stig.load_config(str(cfg), audit)


def test_config_accepts_restricted(tmp_path, audit):
    cfg = tmp_path / "config.json"
    cfg.write_text('{"pusher": "filesystem"}')
    os.chmod(cfg, 0o600)
    assert stig.load_config(str(cfg), audit) == {"pusher": "filesystem"}


# ---------------------------------------------------------------------------
# Encryption at rest
# ---------------------------------------------------------------------------
def test_encryption_roundtrip(sample_pcap, tmp_path, audit, monkeypatch):
    monkeypatch.setenv(stig.SEGMENT_KEY_ENV, stig.generate_segment_key())
    out = tmp_path / "enc"
    extractor = SegmentExtractor(str(out), encrypt=True, audit_logger=audit)
    segments = extractor.extract_segments(sample_pcap, strategy=STRATEGY_PROTOCOL)

    for seg in segments:
        assert seg.encrypted
        assert seg.pcap_path.endswith(".enc")
        assert not os.path.exists(seg.pcap_path[:-4])  # plaintext removed
        decrypted = stig.decrypt_file(seg.pcap_path,
                                      out_path=str(tmp_path / "dec.pcap"),
                                      audit_logger=audit)
        # Decrypted content must match the original (pre-encryption) checksum.
        assert stig.sha256_file(decrypted) == seg.checksum


# ---------------------------------------------------------------------------
# Filesystem pusher
# ---------------------------------------------------------------------------
def test_filesystem_pusher_end_to_end(sample_pcap, tmp_path, audit):
    out = tmp_path / "segs"
    dest = tmp_path / "dest"
    extractor = SegmentExtractor(str(out), audit_logger=audit)
    segments = extractor.extract_segments(sample_pcap, strategy=STRATEGY_PROTOCOL)

    pusher = FilesystemPusher(dest_dir=str(dest), audit_logger=audit)
    for seg in segments:
        assert pusher.push(seg) is True

    pushed_pcaps = [f for f in os.listdir(dest) if f.endswith(".pcap")]
    assert len(pushed_pcaps) == len(segments)
    for seg in segments:
        copied = dest / os.path.basename(seg.pcap_path)
        assert stig.sha256_file(str(copied)) == seg.checksum
        assert stat.S_IMODE(os.stat(copied).st_mode) == 0o600


def test_envelope_roundtrip(sample_pcap, tmp_path, audit):
    out = tmp_path / "env"
    extractor = SegmentExtractor(str(out), audit_logger=audit)
    seg = extractor.extract_segments(sample_pcap, strategy=STRATEGY_PROTOCOL)[0]
    pusher = FilesystemPusher(dest_dir=str(tmp_path / "envdest"), audit_logger=audit)
    envelope = pusher._build_envelope(seg)
    decoded = base64.b64decode(envelope["pcap_b64"])
    assert stig.sha256_bytes(decoded) == seg.checksum
    assert envelope["sha256"] == seg.checksum

"""
Pluggable segment push interface for the unified containerized platform.

Each :class:`SegmentPusher` takes a :class:`dshell.segment_extractor.Segment` and
delivers it to a downstream transport. The base class centralizes the behaviour
mandated by the STIG controls:

    * SHA-256 integrity verification before and after push (V-222553)
    * configurable retry with exponential backoff
    * full audit logging of every attempt and outcome (V-222601)
    * sanitized external error messages (V-222612)

Concrete transports:
    * :class:`FilesystemPusher` - watched-directory / volume-mount integration.
    * :class:`RedisPusher`      - Redis stream queue integration.
    * :class:`KafkaPusher`      - Kafka topic / enterprise message bus (SSL).
    * :class:`RESTAPIPusher`    - HTTPS endpoint with mTLS client cert auth.

Heavy third-party clients (redis, kafka, requests) are imported lazily inside
the relevant pusher so the module imports cleanly without them installed.
"""

import base64
import json
import logging
import os
import shutil
import time
from abc import ABC, abstractmethod
from typing import Optional

from dshell import stig
from dshell.segment_extractor import Segment

logger = logging.getLogger(__name__)


class SegmentPusher(ABC):
    """
    Abstract base class for segment transports.

    Subclasses implement :meth:`_deliver`. Callers use :meth:`push`, which adds
    integrity verification, retry/backoff and audit logging around delivery.
    """

    transport = "abstract"

    def __init__(self, max_retries: int = 3, backoff_base: float = 0.5,
                 backoff_max: float = 30.0, audit_logger: stig.AuditLogger = None):
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self.audit = audit_logger or stig.AuditLogger()

    # -- public API --------------------------------------------------------
    def push(self, segment: Segment) -> bool:
        """
        Push a segment to the configured transport with retry and auditing.

        Returns True on success; raises :class:`dshell.stig.SecureError` after
        exhausting retries (generic message only; details go to the audit log).
        """
        self._verify_integrity(segment)

        destination = self.describe_destination()
        last_exc: Optional[Exception] = None

        for attempt in range(1, self.max_retries + 1):
            try:
                self._deliver(segment)
                self.audit.log("push", True, source=segment.pcap_path,
                               destination=destination, transport=self.transport,
                               attempt=attempt, sha256=segment.checksum)
                logger.info("Pushed %s via %s (attempt %d)",
                            segment.pcap_path, self.transport, attempt)
                return True
            except Exception as exc:  # noqa: BLE001 - logged & retried below
                last_exc = exc
                self.audit.log("push", False, source=segment.pcap_path,
                               destination=destination, transport=self.transport,
                               attempt=attempt, error=str(exc))
                if attempt < self.max_retries:
                    delay = min(self.backoff_base * (2 ** (attempt - 1)),
                                self.backoff_max)
                    logger.warning("Push attempt %d/%d failed; retrying in %.1fs",
                                   attempt, self.max_retries, delay)
                    time.sleep(delay)

        raise stig.sanitize_exception(self.audit, "push", last_exc,
                                      source=segment.pcap_path,
                                      destination=destination)

    @abstractmethod
    def _deliver(self, segment: Segment) -> None:
        """Transport-specific delivery of a single segment. Override required.

        Transports that need the base64 JSON envelope build it on demand via
        :meth:`_build_envelope`; those that stream the file (filesystem, REST)
        avoid the extra in-memory copy entirely.
        """

    def describe_destination(self) -> str:
        """Human-readable destination for audit logs (override as needed)."""
        return self.transport

    # -- helpers -----------------------------------------------------------
    def _verify_integrity(self, segment: Segment) -> None:
        """STIG V-222553: confirm the on-disk segment matches its checksum."""
        if not stig.verify_checksum(segment.pcap_path, segment.checksum,
                                    self.audit, context=segment.pcap_path):
            raise stig.STIGComplianceError(
                f"STIG {stig.STIG_INTEGRITY}: integrity check failed for "
                f"{segment.pcap_path} before push")

    @staticmethod
    def _read_pcap_bytes(segment: Segment) -> bytes:
        with open(segment.pcap_path, "rb") as fh:
            return fh.read()

    def _build_envelope(self, segment: Segment) -> dict:
        """
        Serialize the segment as a JSON envelope with base64 PCAP bytes, the
        metadata manifest and the SHA-256 integrity hash.
        """
        raw = self._read_pcap_bytes(segment)
        return {
            "segment_id": segment.metadata.get("segment_id"),
            "metadata": segment.metadata,
            "sha256": segment.checksum,
            "encrypted": segment.encrypted,
            "pcap_b64": base64.b64encode(raw).decode("ascii"),
        }


class FilesystemPusher(SegmentPusher):
    """
    Write segments to a watched directory (volume-mount container integration).

    The PCAP file is streamed to the destination and accompanied by its JSON
    metadata manifest; both are written with 0o600 permissions into a 0o700
    destination directory (STIG V-222425). The base64 envelope used by the
    network transports is intentionally not written here to avoid duplicating
    the (potentially large) PCAP payload on disk.
    """

    transport = "filesystem"

    def __init__(self, dest_dir: str, **kwargs):
        super().__init__(**kwargs)
        self.dest_dir = stig.secure_dir(dest_dir)

    def describe_destination(self) -> str:
        return self.dest_dir

    def _deliver(self, segment: Segment) -> None:
        seg_id = segment.metadata.get("segment_id", "segment")
        pcap_dest = os.path.join(self.dest_dir, os.path.basename(segment.pcap_path))
        shutil.copyfile(segment.pcap_path, pcap_dest)
        stig.secure_file(pcap_dest)

        manifest_dest = os.path.join(self.dest_dir, f"segment_{seg_id}.manifest.json")
        with open(manifest_dest, "w", encoding="utf-8") as fh:
            json.dump(segment.metadata, fh, default=str)
        stig.secure_file(manifest_dest)

        # STIG V-222553: confirm the copied file matches the original checksum.
        if not stig.verify_checksum(pcap_dest, segment.checksum, self.audit,
                                    context=pcap_dest):
            raise stig.STIGComplianceError(
                f"STIG {stig.STIG_INTEGRITY}: checksum mismatch after write to "
                f"{pcap_dest}")


class RedisPusher(SegmentPusher):
    """
    Push segments to a Redis stream (lightweight queue-based integration).

    The Redis password is loaded exclusively from the environment
    (STIG V-222404) via ``password_env`` (default ``DSHELL_REDIS_PASSWORD``).
    """

    transport = "redis"

    def __init__(self, host: str = "localhost", port: int = 6379, db: int = 0,
                 stream: str = "dshell-segments", use_tls: bool = False,
                 password_env: str = "DSHELL_REDIS_PASSWORD", **kwargs):
        super().__init__(**kwargs)
        self.host = host
        self.port = port
        self.db = db
        self.stream = stream
        self.use_tls = use_tls
        self.password = os.environ.get(password_env)
        self._client = None

    def describe_destination(self) -> str:
        scheme = "rediss" if self.use_tls else "redis"
        return f"{scheme}://{self.host}:{self.port}/{self.db}#{self.stream}"

    def _get_client(self):
        if self._client is None:
            import redis  # lazy import
            self._client = redis.Redis(
                host=self.host, port=self.port, db=self.db,
                password=self.password, ssl=self.use_tls,
                socket_timeout=10, socket_connect_timeout=10,
            )
        return self._client

    def _deliver(self, segment: Segment) -> None:
        envelope = self._build_envelope(segment)
        client = self._get_client()
        client.xadd(self.stream, {
            "segment_id": str(envelope.get("segment_id")),
            "sha256": segment.checksum,
            "metadata": json.dumps(segment.metadata, default=str),
            "pcap_b64": envelope["pcap_b64"],
        })


class KafkaPusher(SegmentPusher):
    """
    Push segments to a Kafka topic (enterprise message bus integration).

    STIG V-222602: ``security.protocol`` is forced to ``SSL``. SASL credentials,
    if used, are loaded from the environment (STIG V-222404).
    """

    transport = "kafka"

    def __init__(self, bootstrap_servers: str, topic: str = "dshell-segments",
                 ssl_cafile: str = None, ssl_certfile: str = None,
                 ssl_keyfile: str = None,
                 sasl_username_env: str = "DSHELL_KAFKA_USERNAME",
                 sasl_password_env: str = "DSHELL_KAFKA_PASSWORD", **kwargs):
        super().__init__(**kwargs)
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.ssl_cafile = ssl_cafile
        self.ssl_certfile = ssl_certfile
        self.ssl_keyfile = ssl_keyfile
        self.sasl_username = os.environ.get(sasl_username_env)
        self.sasl_password = os.environ.get(sasl_password_env)
        self._producer = None

    def describe_destination(self) -> str:
        return f"kafka://{self.bootstrap_servers}#{self.topic}"

    def _get_producer(self):
        if self._producer is None:
            from kafka import KafkaProducer  # lazy import
            config = {
                "bootstrap_servers": self.bootstrap_servers,
                # STIG V-222602: require encrypted transport.
                "security_protocol": "SASL_SSL" if self.sasl_password else "SSL",
                "ssl_cafile": self.ssl_cafile,
                "ssl_certfile": self.ssl_certfile,
                "ssl_keyfile": self.ssl_keyfile,
                "value_serializer": lambda v: json.dumps(v, default=str).encode("utf-8"),
            }
            if self.sasl_password:
                config["sasl_mechanism"] = "PLAIN"
                config["sasl_plain_username"] = self.sasl_username
                config["sasl_plain_password"] = self.sasl_password
            self._producer = KafkaProducer(**config)
        return self._producer

    def _deliver(self, segment: Segment) -> None:
        envelope = self._build_envelope(segment)
        producer = self._get_producer()
        future = producer.send(self.topic, envelope)
        future.get(timeout=30)
        producer.flush()


class RESTAPIPusher(SegmentPusher):
    """
    POST segments to an HTTPS endpoint with mTLS client-certificate auth.

    STIG V-222602: TLS 1.2+ with certificate verification (self-signed rejected
    by default). STIG V-222577: a short-lived bearer token accompanies each
    request; no persistent session cookies are stored.
    """

    transport = "rest"

    def __init__(self, url: str, client_cert: str, client_key: str = None,
                 ca_bundle: str = None, allow_self_signed: bool = False,
                 token_ttl: int = 300, timeout: int = 30, **kwargs):
        super().__init__(**kwargs)
        self.url = url
        self.client_cert = client_cert
        self.client_key = client_key
        self.ca_bundle = ca_bundle
        self.allow_self_signed = allow_self_signed
        self.token_ttl = token_ttl
        self.timeout = timeout
        if not url.lower().startswith("https://"):
            raise stig.STIGComplianceError(
                f"STIG {stig.STIG_ENCRYPTION_TRANSIT}: REST endpoint must use "
                f"HTTPS, got {url!r}")

    def describe_destination(self) -> str:
        return self.url

    def _deliver(self, segment: Segment) -> None:
        session = stig.build_tls_session(
            client_cert=self.client_cert, client_key=self.client_key,
            ca_bundle=self.ca_bundle, allow_self_signed=self.allow_self_signed,
            audit_logger=self.audit)
        try:
            token = stig.SessionToken(self.token_ttl)
            headers = {"Authorization": f"Bearer {token.value()}"}
            files = {
                "manifest": ("manifest.json",
                             json.dumps(segment.metadata, default=str),
                             "application/json"),
                "segment": (os.path.basename(segment.pcap_path),
                            self._read_pcap_bytes(segment),
                            "application/vnd.tcpdump.pcap"),
            }
            data = {"sha256": segment.checksum,
                    "segment_id": str(segment.metadata.get("segment_id"))}
            response = session.post(self.url, files=files, data=data,
                                    headers=headers, timeout=self.timeout)
            response.raise_for_status()
        finally:
            # No persistent session cookies (STIG V-222577).
            session.close()

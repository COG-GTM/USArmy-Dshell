"""
DoD STIG compliance utilities for the Dshell segment extractor/pusher tooling.

This module centralizes the security controls required by the relevant
Application Security and Development STIG rules. Every control is enforced
programmatically and emits log messages that reference the specific STIG ID so
that audit reviewers can trace enforcement back to the requirement.

Controls implemented here:
    V-222596 - Input validation (PCAP path / magic byte validation)
    V-222601 - Structured audit logging
    V-222612 - Error handling (generic external messages, full internal logging)
    V-222602 - Encryption in transit (TLS 1.2+, certificate verification)
    V-222659 - Encryption at rest (AES-256-GCM)
    V-222425 - File / directory permissions and umask verification
    V-222577 - Session management (short lived tokens)
    V-222404 - No hardcoded credentials (env / restricted config files only)
    V-222553 - Integrity verification (SHA-256 checksums)
"""

import base64
import getpass
import hashlib
import json
import logging
import os
import secrets
import ssl
import stat
import time
import traceback
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

# STIG identifiers, referenced in log messages so enforcement is auditable.
STIG_INPUT_VALIDATION = "V-222596"
STIG_AUDIT_LOGGING = "V-222601"
STIG_ERROR_HANDLING = "V-222612"
STIG_ENCRYPTION_TRANSIT = "V-222602"
STIG_ENCRYPTION_REST = "V-222659"
STIG_FILE_PERMISSIONS = "V-222425"
STIG_SESSION_MGMT = "V-222577"
STIG_NO_HARDCODED_CREDS = "V-222404"
STIG_INTEGRITY = "V-222553"
STIG_NON_ROOT = "V-222432"

# Secure permission masks.
SECURE_FILE_MODE = 0o600
SECURE_DIR_MODE = 0o700
SECURE_UMASK = 0o077

# Environment variable that supplies the AES-256-GCM key. Never hardcode keys.
SEGMENT_KEY_ENV = "DSHELL_SEGMENT_KEY"
AUDIT_LOG_ENV = "DSHELL_AUDIT_LOG"

# Magic bytes for classic pcap (both endiannesses, us/ns) and pcap-ng.
_PCAP_MAGIC_BYTES = (
    b"\xa1\xb2\xc3\xd4",  # classic pcap, big endian, microsecond
    b"\xd4\xc3\xb2\xa1",  # classic pcap, little endian, microsecond
    b"\xa1\xb2\x3c\x4d",  # classic pcap, big endian, nanosecond
    b"\x4d\x3c\xb2\xa1",  # classic pcap, little endian, nanosecond
)
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"  # pcap-ng section header block type

logger = logging.getLogger(__name__)


class STIGComplianceError(Exception):
    """Raised when a STIG control rejects an operation."""


class SecureError(Exception):
    """
    Generic, sanitized error surfaced to the user (STIG V-222612).

    The detailed cause is logged to the audit log; only this generic message is
    ever shown on stdout/stderr.
    """


# ---------------------------------------------------------------------------
# STIG V-222601 - Audit logging
# ---------------------------------------------------------------------------
class _JSONAuditFormatter(logging.Formatter):
    """Formatter that passes through pre-serialized JSON audit records."""

    def format(self, record: logging.LogRecord) -> str:
        return record.getMessage()


class AuditLogger:
    """
    Structured JSON audit logger (STIG V-222601).

    Logs user, timestamp, action, source, destination, outcome and error
    details to a rotating file whose permissions are restricted to 0o600.
    """

    def __init__(self, log_path: str = None, name: str = "dshell.audit",
                 max_bytes: int = 5 * 1024 * 1024, backup_count: int = 5):
        self.log_path = log_path or os.environ.get(AUDIT_LOG_ENV) or os.path.join(
            os.getcwd(), "dshell_audit.log")
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        if not any(getattr(h, "_dshell_audit", False) for h in self.logger.handlers):
            log_dir = os.path.dirname(self.log_path) or "."
            os.makedirs(log_dir, exist_ok=True)
            handler = RotatingFileHandler(
                self.log_path, maxBytes=max_bytes, backupCount=backup_count)
            handler.setFormatter(_JSONAuditFormatter())
            handler._dshell_audit = True
            self.logger.addHandler(handler)
            # Restrict permissions on the audit log itself (STIG V-222425).
            try:
                os.chmod(self.log_path, SECURE_FILE_MODE)
            except OSError:
                logger.warning("STIG %s: could not set 0o600 on audit log %s",
                               STIG_FILE_PERMISSIONS, self.log_path)

    def _emit(self, level: int, action: str, success: bool, source: str = None,
              destination: str = None, error: str = None, stig: str = None,
              event: str = "operation", **extra) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user": _current_user(),
            "pid": os.getpid(),
            "event": event,
            "action": action,
            "source": source,
            "destination": destination,
            "outcome": "success" if success else "failure",
            "error": error,
            "stig": stig,
        }
        record.update(extra)
        self.logger.log(level, json.dumps(record, default=str))

    def log(self, action: str, success: bool, **kwargs) -> None:
        """Record a normal operation outcome (extract/push/delete/...)."""
        self._emit(logging.INFO if success else logging.ERROR,
                   action, success, **kwargs)

    def security_event(self, action: str, error: str = None, **kwargs) -> None:
        """Record a security-relevant event (e.g. checksum mismatch)."""
        kwargs.pop("event", None)
        self._emit(logging.WARNING, action, False, error=error,
                   event="security", **kwargs)


def _current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"


# ---------------------------------------------------------------------------
# STIG V-222612 - Error handling
# ---------------------------------------------------------------------------
def sanitize_exception(audit_logger: "AuditLogger", action: str, exc: Exception,
                       source: str = None, destination: str = None,
                       stig: str = STIG_ERROR_HANDLING) -> SecureError:
    """
    Log the full traceback to the audit log and return a SecureError carrying
    only a generic message (STIG V-222612). Callers raise the returned error so
    that no stack trace or internal path reaches stdout/stderr.
    """
    detail = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    audit_logger.log(action, False, source=source, destination=destination,
                     error=detail, stig=stig)
    return SecureError(f"Operation '{action}' failed. See audit log for details.")


# ---------------------------------------------------------------------------
# STIG V-222596 - Input validation
# ---------------------------------------------------------------------------
def safe_path(path: str, base: str = None, audit_logger: "AuditLogger" = None) -> str:
    """
    Canonicalize ``path`` and reject directory traversal (STIG V-222596).

    The path is resolved to an absolute, symlink-free location with
    :func:`os.path.realpath`. Any ``..`` traversal component is rejected. When a
    ``base`` directory is supplied, the resolved path MUST remain inside that
    base (verified with :func:`os.path.commonpath`), preventing CLI arguments
    from escaping the intended directory. Returns the validated absolute path;
    all downstream filesystem access must use this return value, never the raw
    input.
    """
    if not path:
        _reject_input(audit_logger, path, "empty path")
    if ".." in str(path).replace("\\", "/").split("/"):
        _reject_input(audit_logger, path, "path traversal sequence rejected")

    resolved = os.path.realpath(path)

    if base is not None:
        base_resolved = os.path.realpath(base)
        if os.path.commonpath([base_resolved, resolved]) != base_resolved:
            _reject_input(audit_logger, path,
                          f"resolved path escapes permitted base {base!r}")

    return resolved


def validate_pcap_path(path: str, audit_logger: "AuditLogger" = None,
                       base: str = None) -> str:
    """
    Validate a PCAP input path (STIG V-222596).

    Rejects path traversal, requires a regular file, and verifies the file
    magic bytes match a PCAP or PCAP-NG format before processing. An optional
    ``base`` confines the input to a permitted directory.

    Returns the resolved absolute path or raises STIGComplianceError.
    """
    resolved = safe_path(path, base=base, audit_logger=audit_logger)
    if not os.path.exists(resolved):
        _reject_input(audit_logger, path, "file does not exist")
    if not os.path.isfile(resolved):
        _reject_input(audit_logger, path, "not a regular file")

    try:
        with open(resolved, "rb") as fh:
            magic = fh.read(4)
    except OSError as exc:
        _reject_input(audit_logger, path, f"unreadable file: {exc.strerror}")

    if magic not in _PCAP_MAGIC_BYTES and magic != _PCAPNG_MAGIC:
        _reject_input(audit_logger, path, "magic bytes do not match PCAP/PCAP-NG")

    return resolved


def _reject_input(audit_logger, path, reason):
    msg = f"STIG {STIG_INPUT_VALIDATION}: Input validation failed for path {path!r}: {reason}"
    if audit_logger:
        audit_logger.security_event("input_validation", error=msg, source=path,
                                    stig=STIG_INPUT_VALIDATION)
    logger.error(msg)
    raise STIGComplianceError(msg)


# ---------------------------------------------------------------------------
# STIG V-222425 - File permissions / umask
# ---------------------------------------------------------------------------
def verify_umask(audit_logger: "AuditLogger" = None) -> int:
    """
    Verify and enforce a restrictive umask (STIG V-222425).

    Returns the effective umask after enforcement.
    """
    current = os.umask(SECURE_UMASK)
    if current & SECURE_UMASK != SECURE_UMASK:
        msg = (f"STIG {STIG_FILE_PERMISSIONS}: umask {oct(current)} was too "
               f"permissive; enforced {oct(SECURE_UMASK)}")
        logger.warning(msg)
        if audit_logger:
            audit_logger.log("umask_check", True, error=msg,
                             stig=STIG_FILE_PERMISSIONS)
    return SECURE_UMASK


def secure_file(path: str) -> str:
    """Set a created file to 0o600 (STIG V-222425)."""
    resolved = safe_path(path)
    os.chmod(resolved, SECURE_FILE_MODE)
    return resolved


def secure_dir(path: str) -> str:
    """Create (if needed) and set a directory to 0o700 (STIG V-222425)."""
    resolved = safe_path(path)
    os.makedirs(resolved, exist_ok=True)
    os.chmod(resolved, SECURE_DIR_MODE)
    return resolved


# ---------------------------------------------------------------------------
# STIG V-222553 - Integrity verification
# ---------------------------------------------------------------------------
def sha256_file(path: str) -> str:
    """Compute the SHA-256 hex digest of a file (STIG V-222553)."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Compute the SHA-256 hex digest of a byte string."""
    return hashlib.sha256(data).hexdigest()


def verify_checksum(path: str, expected: str, audit_logger: "AuditLogger" = None,
                    context: str = None) -> bool:
    """
    Verify a file matches an expected SHA-256 digest (STIG V-222553).

    Logs a security event on mismatch and returns False.
    """
    actual = sha256_file(path)
    if not secrets.compare_digest(actual, expected):
        msg = (f"STIG {STIG_INTEGRITY}: checksum mismatch for {context or path} "
               f"(expected {expected}, got {actual})")
        logger.error(msg)
        if audit_logger:
            audit_logger.security_event("checksum_verify", error=msg,
                                        source=path, stig=STIG_INTEGRITY)
        return False
    return True


# ---------------------------------------------------------------------------
# STIG V-222404 - No hardcoded credentials / restricted config files
# ---------------------------------------------------------------------------
def load_config(path: str, audit_logger: "AuditLogger" = None) -> dict:
    """
    Load a YAML/JSON config file, refusing to start if it is world/group
    readable (STIG V-222404). Credentials must come from such restricted files
    or the environment, never from hardcoded values.
    """
    resolved = safe_path(path, audit_logger=audit_logger)
    if not os.path.isfile(resolved):
        raise STIGComplianceError(
            f"STIG {STIG_NO_HARDCODED_CREDS}: config file not found: {path!r}")

    mode = stat.S_IMODE(os.stat(resolved).st_mode)
    if mode & 0o077:
        msg = (f"STIG {STIG_NO_HARDCODED_CREDS}: refusing to load config "
               f"{path!r} with permissive mode {oct(mode)}; require 0o600")
        if audit_logger:
            audit_logger.security_event("config_load", error=msg, source=path,
                                        stig=STIG_NO_HARDCODED_CREDS)
        raise STIGComplianceError(msg)

    with open(resolved, "r", encoding="utf-8") as fh:
        text = fh.read()

    if resolved.endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError as exc:
            raise STIGComplianceError(
                "pyyaml is required to parse YAML config files") from exc
        return yaml.safe_load(text) or {}
    return json.loads(text) if text.strip() else {}


def require_secret(name: str, audit_logger: "AuditLogger" = None) -> str:
    """
    Fetch a credential exclusively from the environment (STIG V-222404).
    """
    value = os.environ.get(name)
    if not value:
        msg = (f"STIG {STIG_NO_HARDCODED_CREDS}: required credential {name} not "
               f"set in environment")
        if audit_logger:
            audit_logger.security_event("credential_load", error=msg,
                                        stig=STIG_NO_HARDCODED_CREDS)
        raise STIGComplianceError(msg)
    return value


# ---------------------------------------------------------------------------
# STIG V-222659 - Encryption at rest (AES-256-GCM)
# ---------------------------------------------------------------------------
def _segment_key(audit_logger: "AuditLogger" = None) -> bytes:
    """
    Resolve the AES-256 key from the environment (STIG V-222404 / V-222659).
    Accepts a base64 or hex encoded 32-byte key.
    """
    raw = require_secret(SEGMENT_KEY_ENV, audit_logger)
    key = None
    for decoder in (base64.b64decode, bytes.fromhex):
        try:
            candidate = decoder(raw)
            if len(candidate) == 32:
                key = candidate
                break
        except (ValueError, base64.binascii.Error):
            continue
    if key is None:
        raise STIGComplianceError(
            f"STIG {STIG_ENCRYPTION_REST}: {SEGMENT_KEY_ENV} must be a base64 or "
            f"hex encoded 32-byte (AES-256) key")
    return key


def generate_segment_key() -> str:
    """Generate a fresh base64-encoded AES-256 key for operator convenience."""
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def encrypt_file(path: str, audit_logger: "AuditLogger" = None,
                 remove_plaintext: bool = True) -> str:
    """
    Encrypt a file at rest with AES-256-GCM (STIG V-222659).

    Output layout: 12-byte nonce || ciphertext+tag, written to ``path + '.enc'``
    with 0o600 permissions. Returns the encrypted file path.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = _segment_key(audit_logger)
    nonce = secrets.token_bytes(12)
    with open(path, "rb") as fh:
        plaintext = fh.read()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    enc_path = path + ".enc"
    with open(enc_path, "wb") as fh:
        fh.write(nonce + ciphertext)
    secure_file(enc_path)
    if remove_plaintext:
        os.remove(path)
    if audit_logger:
        audit_logger.log("encrypt_at_rest", True, source=path, destination=enc_path,
                         stig=STIG_ENCRYPTION_REST)
    return enc_path


def decrypt_file(enc_path: str, out_path: str = None,
                 audit_logger: "AuditLogger" = None) -> str:
    """Decrypt a file produced by :func:`encrypt_file` (STIG V-222659)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = _segment_key(audit_logger)
    with open(enc_path, "rb") as fh:
        blob = fh.read()
    nonce, ciphertext = blob[:12], blob[12:]
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)

    out_path = out_path or (enc_path[:-4] if enc_path.endswith(".enc") else enc_path + ".dec")
    with open(out_path, "wb") as fh:
        fh.write(plaintext)
    secure_file(out_path)
    return out_path


# ---------------------------------------------------------------------------
# STIG V-222577 - Session management (short lived tokens)
# ---------------------------------------------------------------------------
class SessionToken:
    """A short-lived, non-persistent bearer token (STIG V-222577)."""

    def __init__(self, ttl_seconds: int = 300):
        self.ttl_seconds = ttl_seconds
        self.token = secrets.token_urlsafe(32)
        self.expires_at = time.time() + ttl_seconds

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at

    def value(self) -> str:
        if self.expired:
            raise STIGComplianceError(
                f"STIG {STIG_SESSION_MGMT}: session token expired")
        return self.token


# ---------------------------------------------------------------------------
# STIG V-222602 - Encryption in transit (TLS 1.2+)
# ---------------------------------------------------------------------------
def build_tls_session(client_cert: str = None, client_key: str = None,
                      ca_bundle: str = None, allow_self_signed: bool = False,
                      audit_logger: "AuditLogger" = None):
    """
    Build a ``requests.Session`` that enforces TLS 1.2+ and certificate
    verification (STIG V-222602). Optionally configures an mTLS client cert.

    Server certificate verification is ALWAYS enforced. Self-signed certificates
    are rejected by default; the ``allow_self_signed`` override does not disable
    verification -- instead it pins trust to the certificate(s) supplied in
    ``ca_bundle`` (so a private/self-signed CA can be trusted explicitly). When
    ``allow_self_signed`` is set, ``ca_bundle`` is therefore required.
    """
    import requests
    from requests.adapters import HTTPAdapter

    try:
        from urllib3.util.ssl_ import create_urllib3_context
    except ImportError:  # pragma: no cover - urllib3 always present with requests
        create_urllib3_context = None

    class _TLS12Adapter(HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            if create_urllib3_context is not None:
                ctx = create_urllib3_context()
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                kwargs["ssl_context"] = ctx
            return super().init_poolmanager(*args, **kwargs)

    session = requests.Session()
    session.mount("https://", _TLS12Adapter())

    if client_cert:
        session.cert = (client_cert, client_key) if client_key else client_cert

    if allow_self_signed:
        if not ca_bundle:
            raise STIGComplianceError(
                f"STIG {STIG_ENCRYPTION_TRANSIT}: allow_self_signed requires a "
                f"ca_bundle to pin trust to; refusing to disable verification")
        msg = (f"STIG {STIG_ENCRYPTION_TRANSIT}: trusting pinned self-signed CA "
               f"bundle {ca_bundle!r}; server certificate verification remains on")
        logger.warning(msg)
        if audit_logger:
            audit_logger.security_event("tls_config", error=msg,
                                        stig=STIG_ENCRYPTION_TRANSIT)

    # Verification is never disabled: pin to the supplied CA bundle when given,
    # otherwise use the system trust store.
    session.verify = ca_bundle if ca_bundle else True

    return session


# ---------------------------------------------------------------------------
# Startup compliance check
# ---------------------------------------------------------------------------
def stig_check(audit_logger: "AuditLogger" = None, config_path: str = None) -> dict:
    """
    Run all startup STIG compliance checks and log the results.

    Returns a dict of check name -> bool (passed). Non-fatal checks log
    warnings; this function never raises so the CLI can decide how to react.
    """
    audit_logger = audit_logger or AuditLogger()
    results = {}

    # V-222425: umask
    try:
        verify_umask(audit_logger)
        results["umask"] = True
    except Exception:
        results["umask"] = False

    # V-222432: non-root execution. Root is discouraged for this passive tool.
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    results["non_root"] = not is_root
    if is_root:
        logger.warning("STIG %s: running as root is discouraged", STIG_NON_ROOT)

    # V-222659: encryption key availability (informational only).
    results["segment_key_present"] = bool(os.environ.get(SEGMENT_KEY_ENV))

    # V-222404: config file permissions, if a config was supplied.
    if config_path:
        try:
            load_config(config_path, audit_logger)
            results["config_permissions"] = True
        except STIGComplianceError:
            results["config_permissions"] = False

    audit_logger.log("stig_check", all(results.values()), stig="startup",
                     results=results)
    logger.info("STIG startup check results: %s", results)
    return results

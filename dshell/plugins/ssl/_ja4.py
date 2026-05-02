"""
JA4/JA4S TLS fingerprinting helpers.

This module computes JA4 (TLS ClientHello) and JA4S (TLS ServerHello)
fingerprints directly from the handshake structures already parsed by
``dshell.plugins.ssl.tls``.  It exists because the upstream FoxIO
reference implementation at https://github.com/FoxIO-LLC/ja4 ships
only a tshark-driven CLI -- there is currently no pip-installable
``ja4``/``pyja4`` library that accepts pre-parsed handshakes.  The
algorithm implemented here is adapted from the FoxIO reference and
matches the public JA4 specification.

JA4 (TLS client fingerprint) is licensed under BSD 3-Clause -- see
https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE-JA4

JA4S (TLS server fingerprint) is part of the JA4+ family, licensed
under FoxIO License 1.1 (non-commercial use) -- see
https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE

JA4 specification:
    https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
JA4S specification:
    https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4S.md

Original reference implementation (c) 2023, FoxIO, LLC.
"""

import hashlib
import struct


# Two-byte hex ids of GREASE values (RFC 8701).  These are removed
# before sorting/hashing for JA4 (but kept verbatim for JA4S).
_GREASE = frozenset(
    [
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
        0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
        0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    ]
)

# Map handshake/legacy version -> two-character JA4 version code.
_TLS_VERSION_MAP = {
    0x0002: "s2",
    0x0300: "s3",
    0x0301: "10",
    0x0302: "11",
    0x0303: "12",
    0x0304: "13",
}

# Extension type ids we need to special-case.
_EXT_SERVER_NAME = 0x0000           # SNI -- removed from sorted JA4 ext list
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_SIGNATURE_ALGORITHMS = 0x000D  # used for JA4 part C
_EXT_ALPN = 0x0010                  # provides ALPN value AND removed from sorted ext list
_EXT_SUPPORTED_VERSIONS = 0x002B    # client/server's preferred TLS version


def _sha12(values):
    """Comma-join ``values`` and return the first 12 chars of sha256(hex)."""
    if isinstance(values, (list, tuple)):
        values = ",".join(values)
    return hashlib.sha256(values.encode("utf-8")).hexdigest()[:12]


def _u16(b, off=0):
    """Unpack a big-endian 16-bit int from ``b`` at offset ``off``."""
    return struct.unpack("!H", b[off:off + 2])[0]


def _two_byte_int(value):
    """Coerce a raw cipher/extension id to ``int`` regardless of input type."""
    if isinstance(value, int):
        return value
    if isinstance(value, (bytes, bytearray)) and len(value) == 2:
        return _u16(bytes(value))
    raise TypeError("expected 2-byte value, got %r" % (value,))


def _hex4(value):
    """Format a 16-bit int as a 4-char lowercase hex string (no 0x)."""
    return "{:04x}".format(value & 0xFFFF)


def _alpn_code(first_alpn):
    """Return the 2-char JA4 ALPN code for the first ALPN protocol.

    ``first_alpn`` should be ``bytes`` (as carried in the ALPN extension)
    or ``None``.  ``"00"`` means no ALPN extension was present.
    """
    if not first_alpn:
        return "00"
    if isinstance(first_alpn, (bytes, bytearray)):
        try:
            text = first_alpn.decode("ascii")
        except UnicodeDecodeError:
            # Non-ASCII -> JA4 spec uses literal "99".
            return "99"
    else:
        text = str(first_alpn)
    if not text:
        return "00"
    if ord(text[0]) > 127:
        return "99"
    if len(text) == 1:
        return text + text
    return text[0] + text[-1]


def _parse_alpn_first(ext_data):
    """Return the first ALPN protocol from raw ALPN extension data, or ``None``."""
    if not ext_data or len(ext_data) < 3:
        return None
    # ALPN extension: u16 list_length, then [u8 length, opaque value]*
    list_len = _u16(ext_data, 0)
    body = ext_data[2:2 + list_len]
    if len(body) < 1:
        return None
    proto_len = body[0]
    if proto_len == 0 or len(body) < 1 + proto_len:
        return None
    return bytes(body[1:1 + proto_len])


def _parse_signature_algorithms(ext_data):
    """Return a list of 4-char hex sig-algo ids from a signature_algorithms ext."""
    if not ext_data or len(ext_data) < 2:
        return []
    sig_len = _u16(ext_data, 0)
    body = ext_data[2:2 + sig_len]
    out = []
    for i in range(0, len(body) - 1, 2):
        out.append(_hex4(_u16(body, i)))
    # JA4 keeps signature algorithms in the order presented.
    return out


def _parse_supported_versions_client(ext_data):
    """Return a list of 4-char hex version ids from ClientHello supported_versions."""
    if not ext_data or len(ext_data) < 1:
        return []
    list_len = ext_data[0]
    body = ext_data[1:1 + list_len]
    out = []
    for i in range(0, len(body) - 1, 2):
        out.append(_hex4(_u16(body, i)))
    return out


def _parse_supported_versions_server(ext_data):
    """ServerHello supported_versions extension carries a single 2-byte version."""
    if not ext_data or len(ext_data) < 2:
        return None
    return _hex4(_u16(ext_data, 0))


def _select_version(legacy_version, supported_versions_hex):
    """Return the 2-char JA4 version code, preferring the highest supported_versions."""
    candidates = []
    for v in supported_versions_hex:
        try:
            n = int(v, 16)
        except (TypeError, ValueError):
            continue
        if n in _GREASE:
            continue
        candidates.append(n)
    chosen = max(candidates) if candidates else legacy_version
    return _TLS_VERSION_MAP.get(chosen, "00")


def _ext_iter(raw_extensions):
    """Yield ``(ex_type, ex_data)`` pairs from Dshell's raw_extensions list."""
    for ex_type, ex_data in raw_extensions or ():
        yield int(ex_type), bytes(ex_data) if ex_data else b""


def _ciphers_hex_no_grease(cipher_suites):
    """Return list of 4-char hex cipher ids with GREASE values stripped."""
    out = []
    for c in cipher_suites or ():
        n = _two_byte_int(c)
        if n in _GREASE:
            continue
        out.append(_hex4(n))
    return out


def compute_ja4(client_hello, transport="tcp"):
    """Compute the JA4 fingerprint from a parsed TLSClientHello.

    ``client_hello`` must expose the attributes populated by
    ``dshell.plugins.ssl.tls.TLSClientHello``: ``client_version``,
    ``cipher_suites`` (iterable of 2-byte ids), ``raw_extensions``
    (iterable of ``(type, data)``) and ``extensions`` (dict whose
    ``server_name`` key indicates SNI presence).

    Returns a dict with keys ``ja4``, ``ja4_r``, ``ja4_o``, ``ja4_ro``,
    matching the four JA4 forms (hashed/sorted, raw/sorted,
    hashed/original, raw/original).  All values are strings.
    """
    ptype = "q" if transport == "quic" else "t"

    # --- ciphers ---
    ciphers_hex = _ciphers_hex_no_grease(client_hello.cipher_suites)
    cipher_count = "{:02d}".format(min(len(ciphers_hex), 99))
    sorted_ciphers = sorted(ciphers_hex)
    sorted_ciphers_csv = ",".join(sorted_ciphers)
    original_ciphers_csv = ",".join(ciphers_hex)
    sorted_cipher_hash = _sha12(sorted_ciphers) if sorted_ciphers else "000000000000"
    original_cipher_hash = _sha12(ciphers_hex) if ciphers_hex else "000000000000"
    if not ciphers_hex:
        cipher_count = "00"
        sorted_ciphers_csv = ""
        original_ciphers_csv = ""

    # --- extensions / SNI / ALPN / supported_versions / signature_algorithms ---
    ext_ids_hex = []           # all extension ids in original order, no GREASE
    sni_present = False
    first_alpn = None
    supported_versions_hex = []
    signature_algorithms_hex = []

    for ex_type, ex_data in _ext_iter(client_hello.raw_extensions):
        if ex_type in _GREASE:
            continue
        ext_ids_hex.append(_hex4(ex_type))
        if ex_type == _EXT_SERVER_NAME:
            sni_present = True
        elif ex_type == _EXT_ALPN:
            first_alpn = _parse_alpn_first(ex_data)
        elif ex_type == _EXT_SUPPORTED_VERSIONS:
            supported_versions_hex = _parse_supported_versions_client(ex_data)
        elif ex_type == _EXT_SIGNATURE_ALGORITHMS:
            signature_algorithms_hex = _parse_signature_algorithms(ex_data)

    # JA4 ext_count includes ALL non-GREASE extensions (incl. SNI/ALPN).
    ext_count = "{:02d}".format(min(len(ext_ids_hex), 99))

    # For JA4 part C the extension list is sorted, with SNI (0x0000)
    # and ALPN (0x0010) removed before sorting.  The signature_algorithms
    # values are then appended in original order, separated by '_'.
    ext_for_part_c = [
        h for h in ext_ids_hex
        if h not in (_hex4(_EXT_SERVER_NAME), _hex4(_EXT_ALPN))
    ]
    sorted_ext_csv = ",".join(sorted(ext_for_part_c))
    original_ext_csv = ",".join(ext_for_part_c)
    if signature_algorithms_hex:
        sorted_ext_csv = sorted_ext_csv + "_" + ",".join(signature_algorithms_hex)
        original_ext_csv = original_ext_csv + "_" + ",".join(signature_algorithms_hex)

    if sorted_ext_csv:
        sorted_ext_hash = _sha12(sorted_ext_csv)
        original_ext_hash = _sha12(original_ext_csv)
    else:
        sorted_ext_hash = "000000000000"
        original_ext_hash = "000000000000"

    # SNI flag.
    sni_code = "d" if sni_present else "i"

    # Version selection.
    version_code = _select_version(int(client_hello.client_version), supported_versions_hex)

    # ALPN code.
    alpn_code = _alpn_code(first_alpn)

    part_a = "{ptype}{ver}{sni}{cc}{ec}{alpn}".format(
        ptype=ptype, ver=version_code, sni=sni_code,
        cc=cipher_count, ec=ext_count, alpn=alpn_code,
    )

    return {
        "ja4": "{a}_{b}_{c}".format(a=part_a, b=sorted_cipher_hash, c=sorted_ext_hash),
        "ja4_o": "{a}_{b}_{c}".format(a=part_a, b=original_cipher_hash, c=original_ext_hash),
        "ja4_r": "{a}_{b}_{c}".format(a=part_a, b=sorted_ciphers_csv, c=sorted_ext_csv),
        "ja4_ro": "{a}_{b}_{c}".format(a=part_a, b=original_ciphers_csv, c=original_ext_csv),
    }


def compute_ja4s(server_hello, transport="tcp"):
    """Compute the JA4S fingerprint from a parsed TLSServerHello.

    ``server_hello`` must expose ``server_version`` (int), ``cipher_suite``
    (2-byte id), and ``raw_extensions`` (list of ``(type, data)``).  If
    extensions weren't parsed (older Dshell builds), pass an empty list.

    Returns a dict with keys ``ja4s`` (hashed) and ``ja4s_r`` (raw).
    """
    ptype = "q" if transport == "quic" else "t"

    # JA4S keeps extensions in original order and INCLUDES GREASE values.
    ext_ids_hex = []
    first_alpn = None
    supported_versions_hex = []
    for ex_type, ex_data in _ext_iter(getattr(server_hello, "raw_extensions", None)):
        ext_ids_hex.append(_hex4(ex_type))
        if ex_type == _EXT_ALPN:
            first_alpn = _parse_alpn_first(ex_data)
        elif ex_type == _EXT_SUPPORTED_VERSIONS:
            v = _parse_supported_versions_server(ex_data)
            if v is not None:
                supported_versions_hex = [v]

    ext_count = "{:02d}".format(min(len(ext_ids_hex), 99))

    # Selected (and only) cipher.
    if server_hello.cipher_suite is not None:
        cipher_hex = _hex4(_two_byte_int(server_hello.cipher_suite))
    else:
        cipher_hex = ""

    version_code = _select_version(int(server_hello.server_version), supported_versions_hex)
    alpn_code = _alpn_code(first_alpn)

    part_a = "{ptype}{ver}{ec}{alpn}".format(
        ptype=ptype, ver=version_code, ec=ext_count, alpn=alpn_code,
    )

    if ext_ids_hex:
        ext_hash = _sha12(ext_ids_hex)
    else:
        ext_hash = "000000000000"

    return {
        "ja4s": "{a}_{b}_{c}".format(a=part_a, b=cipher_hex, c=ext_hash),
        "ja4s_r": "{a}_{b}_{c}".format(a=part_a, b=cipher_hex, c=",".join(ext_ids_hex)),
    }

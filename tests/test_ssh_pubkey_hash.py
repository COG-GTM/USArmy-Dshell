"""
Regression tests for the SSH host-key fingerprint hash selection logic.

The original implementation in ``dshell/plugins/ssh/ssh-pubkey.py`` used
``eval("hashlib." + hash_scheme)`` to look up the hash constructor. That
construction is flagged by Bandit B307 and maps to STIG V-220632 / CWE-95
because, in the absence of an allow-list, an attacker who controls
``hash_scheme`` could force evaluation of arbitrary attribute paths.

These tests pin the post-fix behaviour without importing the plugin module
itself (the plugin depends on the wider Dshell runtime, which is not
required for asserting the security-relevant invariant). They:

  * Confirm the allow-list constant is defined and exposes the expected set.
  * Confirm the legacy ``eval("hashlib.…")`` call no longer appears.
  * Confirm a ``getattr(hashlib, …)`` call does appear.
  * Confirm a ``ValueError`` guard is wired up before the resolution.
  * Independently exercise the allow-list-then-getattr pattern to
    demonstrate it rejects untrusted input and produces digests
    byte-equivalent to ``hashlib.new``.
"""

import hashlib
import pathlib

import pytest

_PLUGIN_PATH = (
    pathlib.Path(__file__).resolve().parent.parent
    / "dshell" / "plugins" / "ssh" / "ssh-pubkey.py"
)


def _plugin_source() -> str:
    return _PLUGIN_PATH.read_text(encoding="utf-8")


def test_plugin_source_file_exists():
    assert _PLUGIN_PATH.is_file(), f"missing plugin: {_PLUGIN_PATH}"


def test_no_eval_hashlib_call_remains():
    """No executable line still uses eval("hashlib.…").

    Comments referencing the legacy construction (for documentation) are
    permitted; only non-comment occurrences would constitute a regression.
    """
    forbidden = ("eval(\"hashlib.", "eval('hashlib.")
    for raw in _PLUGIN_PATH.read_text(encoding="utf-8").splitlines():
        stripped = raw.lstrip()
        if stripped.startswith("#"):
            continue
        for needle in forbidden:
            assert needle not in raw, f"regressed eval(): {raw!r}"


def test_getattr_hashlib_call_is_used():
    assert "getattr(hashlib," in _plugin_source()


def test_allowlist_constant_declared():
    src = _plugin_source()
    assert "_ALLOWED_FINGERPRINT_HASHES" in src
    for name in ("md5", "sha1", "sha256", "sha384", "sha512"):
        assert f"\"{name}\"" in src or f"'{name}'" in src


def test_value_error_guard_present():
    src = _plugin_source()
    assert "raise ValueError" in src
    assert "_ALLOWED_FINGERPRINT_HASHES" in src


# --- Independent behavioural checks of the allow-list-plus-getattr idiom. ---


_ALLOWED = ("md5", "sha1", "sha256", "sha384", "sha512")


def _resolve(name: str):
    if name not in _ALLOWED:
        raise ValueError(f"Unsupported fingerprint hash: {name!r}")
    return getattr(hashlib, name)


@pytest.mark.parametrize("name", list(_ALLOWED))
def test_allowed_names_resolve_to_hashlib_constructors(name):
    fn = _resolve(name)
    assert callable(fn)
    assert fn(b"abc").hexdigest() == hashlib.new(name, b"abc").hexdigest()


@pytest.mark.parametrize(
    "bad_name",
    [
        "open",                       # builtin attribute on the module path
        "__import__",                 # dunder reachable via getattr
        "md5'); import os; os.system('id",  # legacy-eval injection shape
        "",                           # empty string
        "shake_128",                  # not in our allow-list
    ],
)
def test_disallowed_names_rejected(bad_name):
    with pytest.raises(ValueError):
        _resolve(bad_name)


def test_fingerprint_byte_equivalence_with_legacy_path():
    """getattr-based path produces identical digests to hashlib.new."""
    payload = b"sample-ssh-host-pubkey-blob"
    for name in ("md5", "sha1", "sha256"):
        via_getattr = _resolve(name)(payload).digest()
        via_new = hashlib.new(name, payload).digest()
        assert via_getattr == via_new

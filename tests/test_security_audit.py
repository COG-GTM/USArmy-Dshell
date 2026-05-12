"""
Security-audit regression tests for Dshell v3.2.3.

These tests cover the *fixes* that landed alongside the federal security audit
documented under ``docs/security-audit/``. They are intentionally narrow — each
test corresponds to a finding (F-001 … F-019) so that regressions are easy to
attribute. The companion suite ``tests/test_compliance.py`` covers control-level
STIG / NIST 800-53 assertions.

Run::

    pytest tests/test_security_audit.py -v
"""

from __future__ import annotations

import ast
import hashlib
import logging
import re
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
DSHELL = REPO_ROOT / "dshell"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _ast(path: Path) -> ast.Module:
    return ast.parse(_read(path), filename=str(path))


def _imports(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
    return names


# ---------------------------------------------------------------------------
# F-001 — weak hash w/o usedforsecurity=False
# ---------------------------------------------------------------------------


F001_FILES = [
    DSHELL / "plugins" / "ssl" / "tls.py",
    DSHELL / "plugins" / "ssl" / "sslblacklist.py",
    DSHELL / "plugins" / "http" / "web.py",
    DSHELL / "plugins" / "ssh" / "ssh-pubkey.py",
]


@pytest.mark.parametrize("path", F001_FILES, ids=[p.name for p in F001_FILES])
def test_f001_md5_sha1_calls_pass_usedforsecurity_false(path: Path) -> None:
    """Every hashlib.md5 / hashlib.sha1 call must opt out of FIPS-mode crypto."""
    src = _read(path)

    # Direct calls hashlib.md5(...) without usedforsecurity= would now crash on
    # FIPS systems. We forbid the legacy form; require either hashlib.new with
    # usedforsecurity=False or skip these calls entirely.
    for legacy in ("hashlib.md5(", "hashlib.sha1("):
        if legacy in src:
            pytest.fail(
                f"{path}: legacy {legacy.rstrip('(')} call found; replace with "
                "hashlib.new('md5'|'sha1', ..., usedforsecurity=False)."
            )

    if "hashlib.new(" in src:
        assert "usedforsecurity=False" in src, (
            f"{path}: hashlib.new(...) usage must pass usedforsecurity=False "
            "(F-001 / STIG V-220633 / NIST SC-13, IA-7)."
        )


# ---------------------------------------------------------------------------
# F-002 — Elasticsearch output ships TLS-by-default
# ---------------------------------------------------------------------------


def test_f002_elasticout_defaults_to_https() -> None:
    """ElasticOutput must default to TLS and refuse plaintext without opt-in."""
    src = _read(DSHELL / "output" / "elasticout.py")
    assert 'scheme", "https"' in src, "Default scheme should be https"
    assert "verify_certs" in src, "verify_certs must be configurable"
    assert "refusing to connect over plaintext HTTP" in src, (
        "Plaintext HTTP must raise without an explicit insecure=true opt-in "
        "(STIG V-220634 / NIST SC-8)."
    )


def test_f002_elasticout_refuses_plaintext_without_opt_in() -> None:
    """End-to-end: instantiating ElasticOutput over plaintext must fail."""
    elasticsearch = pytest.importorskip("elasticsearch")  # noqa: F841
    from dshell.output.elasticout import ElasticOutput

    with pytest.raises(ValueError, match="plaintext HTTP"):
        ElasticOutput(scheme="http")


# ---------------------------------------------------------------------------
# F-003 — ssh-pubkey imports sys
# ---------------------------------------------------------------------------


def test_f003_ssh_pubkey_imports_sys() -> None:
    """ssh-pubkey.py must import sys (it references sys.stderr)."""
    path = DSHELL / "plugins" / "ssh" / "ssh-pubkey.py"
    assert "sys" in _imports(_ast(path)), (
        f"{path}: missing `import sys`; would NameError at runtime "
        "(F-003 / STIG V-220641 / NIST SI-11)."
    )


# ---------------------------------------------------------------------------
# F-004 — riphttp initialises `payload` before use
# ---------------------------------------------------------------------------


def test_f004_riphttp_payload_initialised() -> None:
    """`payload` must be unconditionally bound before the `if not payload:` check."""
    path = DSHELL / "plugins" / "http" / "riphttp.py"
    src = _read(path)
    # Locate the http_handler block and assert payload is initialised at the top.
    m = re.search(
        r"def http_handler\(self, conn, request, response\):\n(.*?)\n        if not payload:",
        src,
        flags=re.DOTALL,
    )
    assert m is not None, "http_handler / `if not payload:` block missing"
    body = m.group(1)
    first_assignment = body.split("payload =", 1)[0]
    assert "if" not in first_assignment, (
        "payload must be initialised before any conditional assignment "
        "(F-004 / STIG V-220641 / NIST SI-11)."
    )


# ---------------------------------------------------------------------------
# F-005 — no bare `except:` clauses anywhere under dshell/
# ---------------------------------------------------------------------------


def test_f005_no_bare_except_in_dshell() -> None:
    """Bare except: clauses are forbidden in shipped dshell code (STIG V-220641)."""
    offenders: list[str] = []
    for path in DSHELL.rglob("*.py"):
        try:
            tree = _ast(path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                offenders.append(f"{path}:{node.lineno}")
    assert not offenders, (
        "Bare `except:` clauses found (F-005 / STIG V-220641 / NIST SI-11):\n"
        + "\n".join(offenders)
    )


# ---------------------------------------------------------------------------
# F-008 — eval() must not be used to look up hashlib functions
# ---------------------------------------------------------------------------


def test_f008_no_eval_in_dshell() -> None:
    """`eval()` calls are forbidden in dshell/ (STIG V-220632 / NIST SI-10)."""
    offenders: list[str] = []
    for path in DSHELL.rglob("*.py"):
        for node in ast.walk(_ast(path)):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "eval"
            ):
                offenders.append(f"{path}:{node.lineno}")
    assert not offenders, "Forbidden eval() calls found:\n" + "\n".join(offenders)


# ---------------------------------------------------------------------------
# F-010 — Dockerfile fetches OUI database over HTTPS
# ---------------------------------------------------------------------------


def test_f010_dockerfile_uses_https_for_oui() -> None:
    src = _read(REPO_ROOT / "Dockerfile")
    assert "https://standards-oui.ieee.org/oui/oui.txt" in src, (
        "Dockerfile must fetch OUI database over HTTPS "
        "(F-010 / STIG V-220634 / NIST SC-8)."
    )
    assert "http://standards-oui.ieee.org" not in src


# ---------------------------------------------------------------------------
# F-011 — dependency floors declared
# ---------------------------------------------------------------------------


def test_f011_setup_py_pins_minimum_versions() -> None:
    src = _read(REPO_ROOT / "setup.py")
    for dep in ("geoip2>=", "pcapy-ng>=", "pypacker>=", "pyopenssl>=", "elasticsearch>=", "tabulate>="):
        assert dep in src, f"setup.py missing minimum-version floor for {dep!r}"


def test_f011_requirements_txt_pins_minimum_versions() -> None:
    src = _read(REPO_ROOT / "requirements.txt")
    for dep in ("geoip2>=", "pcapy-ng>=", "pypacker>=", "pyopenssl>=", "elasticsearch>=", "tabulate>="):
        assert dep in src, f"requirements.txt missing minimum-version floor for {dep!r}"


# ---------------------------------------------------------------------------
# F-014 — riphttp try/except/pass blocks were narrowed + logged
# ---------------------------------------------------------------------------


def test_f014_riphttp_no_silent_pass_in_except() -> None:
    path = DSHELL / "plugins" / "http" / "riphttp.py"
    tree = _ast(path)
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            # body is "pass" alone? not allowed
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                pytest.fail(
                    f"riphttp.py:{node.lineno} silently swallows exceptions "
                    "(F-014 / STIG V-220641 / NIST SI-11)."
                )


# ---------------------------------------------------------------------------
# F-019 — Dockerfile drops root in the runtime stage
# ---------------------------------------------------------------------------


def test_f019_dockerfile_runtime_drops_root() -> None:
    src = _read(REPO_ROOT / "Dockerfile")
    assert re.search(r"^USER\s+dshell", src, flags=re.MULTILINE), (
        "Dockerfile runtime stage must include `USER dshell` "
        "(F-019 / STIG V-220629 / NIST AC-6)."
    )
    assert "addgroup" in src and "adduser" in src, (
        "Dockerfile must provision the dshell user before USER directive."
    )


# ---------------------------------------------------------------------------
# Sanity — bandit "known-bad" patterns shouldn't reappear
# ---------------------------------------------------------------------------


KNOWN_BAD = [
    ("os.system(", "shell command injection vector"),
    ("subprocess.call(", "subprocess without shell guard"),
    ("pickle.load(", "deserialization vector"),
    ("yaml.load(", "yaml.load without SafeLoader"),
]


def test_no_high_risk_calls_in_dshell() -> None:
    repo_text = "\n".join(_read(p) for p in DSHELL.rglob("*.py"))
    for needle, reason in KNOWN_BAD:
        assert needle not in repo_text, (
            f"Forbidden pattern {needle!r} found ({reason}); regression of an "
            "audited negative-finding (STIG V-220632 / NIST SI-10)."
        )


# ---------------------------------------------------------------------------
# Quick FIPS smoke — usedforsecurity=False actually works on the running host
# ---------------------------------------------------------------------------


def test_hashlib_new_md5_supports_usedforsecurity_false() -> None:
    """Python >= 3.9 exposes usedforsecurity. We require that capability."""
    h = hashlib.new("md5", b"abc", usedforsecurity=False)
    assert h.hexdigest() == "900150983cd24fb0d6963f7d28e17f72"

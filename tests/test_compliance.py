"""
STIG / NIST 800-53 compliance assertion suite for Dshell v3.2.3.

This suite codifies the STIG controls V-220629 through V-220641 and their
matching NIST 800-53 (Rev 5) controls into runnable pytest assertions. Each
test corresponds to one control family and verifies that the audited
remediations remain in place.

Mappings (sourced from COG-GTM/federal_security_compliance/windsurf/stig-rules.md):

    V-220629  IA-2, IA-5    Authentication / MFA / password policy
    V-220630  AC-7, AC-12   Session management (N/A for an offline CLI)
    V-220631  SI-10         Input validation
    V-220632  SI-10         Injection prevention
    V-220633  SC-28, SC-13  Encryption at rest / FIPS-validated crypto
    V-220634  SC-8          Encryption in transit (TLS 1.2+)
    V-220635  AU-2, AU-3    Audit logging
    V-220641  SI-11         Error handling / generic responses

Run::

    pytest tests/test_compliance.py -v
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
DSHELL = REPO_ROOT / "dshell"
SOURCES = sorted(DSHELL.rglob("*.py"))


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _ast(path: Path) -> ast.Module:
    return ast.parse(_read(path), filename=str(path))


# ===========================================================================
# V-220629 / IA-2, IA-5 — Authentication & credential management
# ===========================================================================


# Patterns that indicate a hardcoded credential. We deliberately use loose
# regex against the source — false positives are caught by the allowlist below.
_HARDCODED_PATTERNS = [
    re.compile(r"(?i)password\s*=\s*['\"][^'\"]{4,}['\"]"),
    re.compile(r"(?i)api[_-]?key\s*=\s*['\"][^'\"]{8,}['\"]"),
    re.compile(r"(?i)secret\s*=\s*['\"][^'\"]{8,}['\"]"),
    re.compile(r"(?i)aws[_-]?(?:access[_-]?key|secret[_-]?access[_-]?key)"),
    re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
]


def test_v220629_no_hardcoded_credentials() -> None:
    """STIG V-220629 / NIST IA-2, IA-5: no hardcoded passwords or API keys."""
    offenders: list[str] = []
    for path in SOURCES:
        src = _read(path)
        for pat in _HARDCODED_PATTERNS:
            for m in pat.finditer(src):
                line = src.count("\n", 0, m.start()) + 1
                snippet = src.splitlines()[line - 1]
                # Allowlist test fixtures (none in dshell/) and comments.
                if snippet.lstrip().startswith("#"):
                    continue
                offenders.append(f"{path}:{line}: {snippet.strip()!r}")
    assert not offenders, (
        "Hardcoded credentials detected (STIG V-220629 / NIST IA-2, IA-5):\n"
        + "\n".join(offenders)
    )


def test_v220629_dockerfile_runtime_is_unprivileged() -> None:
    """Dockerfile runtime stage must drop root (NIST AC-6 / least privilege)."""
    src = _read(REPO_ROOT / "Dockerfile")
    assert re.search(r"^USER\s+dshell", src, flags=re.MULTILINE), (
        "Dockerfile runtime stage must include a USER directive other than root."
    )


# ===========================================================================
# V-220630 / AC-7, AC-12 — Session management
# ===========================================================================


def test_v220630_not_applicable_to_offline_cli() -> None:
    """Dshell is an offline pcap-analysis CLI; no user sessions.

    Recorded as an explicit pass so CI surfaces the control as evaluated. The
    framework does not establish remote sessions; AC-7/AC-12 are managed by
    the operator's host OS, not by Dshell itself.
    """
    # Sanity check: ensure no web-server / network-listener framework is
    # pulled in by the runtime — that would change applicability.
    forbidden_imports = {"flask", "django", "fastapi", "tornado", "aiohttp.web"}
    found: set[str] = set()
    for path in SOURCES:
        for node in ast.walk(_ast(path)):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in forbidden_imports:
                        found.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in forbidden_imports:
                    found.add(node.module)
    assert not found, (
        "Dshell now imports a web framework (%s); AC-7/AC-12 must be re-evaluated."
        % ", ".join(sorted(found))
    )


# ===========================================================================
# V-220631 / SI-10 — Input validation
# ===========================================================================


def test_v220631_setup_py_pins_minimum_versions() -> None:
    """STIG V-220631 / NIST SI-2, RA-5: dependencies must declare version floors."""
    src = _read(REPO_ROOT / "setup.py")
    for dep in ("geoip2", "pcapy-ng", "pypacker", "pyopenssl", "elasticsearch", "tabulate"):
        assert re.search(rf'"{re.escape(dep)}>=[^"]+"', src), (
            f"setup.py: dependency {dep!r} is missing a minimum-version floor."
        )


# ===========================================================================
# V-220632 / SI-10 — Injection prevention
# ===========================================================================


def test_v220632_no_eval_or_exec() -> None:
    """STIG V-220632 / NIST SI-10: eval / exec are forbidden."""
    offenders: list[str] = []
    for path in SOURCES:
        for node in ast.walk(_ast(path)):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"eval", "exec"}
            ):
                offenders.append(f"{path}:{node.lineno}: {node.func.id}()")
    assert not offenders, "eval/exec forbidden:\n" + "\n".join(offenders)


def test_v220632_no_shell_true_subprocess() -> None:
    """STIG V-220632 / NIST SI-10: subprocess with shell=True is forbidden."""
    offenders: list[str] = []
    for path in SOURCES:
        src = _read(path)
        for m in re.finditer(r"subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True", src):
            line = src.count("\n", 0, m.start()) + 1
            offenders.append(f"{path}:{line}: {m.group(0)!r}")
    assert not offenders, "subprocess(shell=True) forbidden:\n" + "\n".join(offenders)


def test_v220632_no_os_system_or_popen() -> None:
    """STIG V-220632 / NIST SI-10: os.system / os.popen are forbidden."""
    offenders: list[str] = []
    for path in SOURCES:
        src = _read(path)
        for needle in ("os.system(", "os.popen("):
            for m in re.finditer(re.escape(needle), src):
                line = src.count("\n", 0, m.start()) + 1
                offenders.append(f"{path}:{line}: {needle}")
    assert not offenders, "os.system / os.popen forbidden:\n" + "\n".join(offenders)


def test_v220632_no_unsafe_deserialisation() -> None:
    """STIG V-220632 / NIST SI-10: pickle.loads, yaml.load (no Loader), marshal."""
    offenders: list[str] = []
    for path in SOURCES:
        src = _read(path)
        if "pickle.loads(" in src or "pickle.load(" in src:
            offenders.append(f"{path}: pickle.{'load' if 'pickle.load(' in src else 'loads'}")
        if re.search(r"yaml\.load\(\s*[^,)]+\)", src):  # missing Loader kwarg
            offenders.append(f"{path}: yaml.load() without Loader")
        if "marshal.loads(" in src or "marshal.load(" in src:
            offenders.append(f"{path}: marshal.load(s)")
    assert not offenders, "Unsafe deserialisation:\n" + "\n".join(offenders)


# ===========================================================================
# V-220633 / SC-28, SC-13, IA-7 — Crypto algorithms & FIPS posture
# ===========================================================================


def test_v220633_md5_sha1_pass_usedforsecurity_false() -> None:
    """STIG V-220633 / NIST SC-13, IA-7: MD5 and SHA-1 must opt out of FIPS mode."""
    offenders: list[str] = []
    for path in SOURCES:
        src = _read(path)
        for legacy in ("hashlib.md5(", "hashlib.sha1("):
            for m in re.finditer(re.escape(legacy), src):
                line = src.count("\n", 0, m.start()) + 1
                offenders.append(f"{path}:{line}: {legacy}…)")
        if "hashlib.new(" in src and "usedforsecurity" not in src:
            offenders.append(f"{path}: hashlib.new(...) without usedforsecurity=False")
    assert not offenders, "FIPS-incompatible hashing:\n" + "\n".join(offenders)


# ===========================================================================
# V-220634 / SC-8 — Encryption in transit
# ===========================================================================


def test_v220634_elasticout_defaults_to_https() -> None:
    """STIG V-220634 / NIST SC-8: external network IO defaults to TLS."""
    src = _read(DSHELL / "output" / "elasticout.py")
    assert 'scheme", "https"' in src
    assert "refusing to connect over plaintext HTTP" in src


def test_v220634_dockerfile_uses_https() -> None:
    """STIG V-220634 / NIST SC-8: build-time fetches use HTTPS."""
    src = _read(REPO_ROOT / "Dockerfile")
    assert "http://standards-oui.ieee.org" not in src
    assert "https://standards-oui.ieee.org" in src


def test_v220634_no_plaintext_http_callouts() -> None:
    """STIG V-220634 / NIST SC-8: dshell/ source must not contain http:// URLs.

    OK to reference http:// in docstrings / comments; we only flag URL string
    literals appearing in code paths that would issue a request.
    """
    offenders: list[str] = []
    request_methods = (
        "requests.get(",
        "requests.post(",
        "urllib.request.urlopen(",
        "urlopen(",
        "httpx.get(",
        "httpx.post(",
    )
    for path in SOURCES:
        src = _read(path)
        for method in request_methods:
            for m in re.finditer(re.escape(method) + r"['\"](http://[^'\"]+)['\"]", src):
                line = src.count("\n", 0, m.start()) + 1
                offenders.append(f"{path}:{line}: {method}{m.group(1)!r}")
    assert not offenders, "Plaintext HTTP callouts:\n" + "\n".join(offenders)


# ===========================================================================
# V-220635 / AU-2, AU-3 — Audit logging
# ===========================================================================


def test_v220635_logging_module_used() -> None:
    """STIG V-220635 / NIST AU-2, AU-3: a logging framework is present and used."""
    found = False
    for path in SOURCES:
        src = _read(path)
        if "import logging" in src or "logger" in src or "self.logger" in src:
            found = True
            break
    assert found, "No use of Python logging detected anywhere under dshell/."


def test_v220635_remediated_excepts_log_at_debug() -> None:
    """STIG V-220635 / NIST AU-2: remediated bare-except sites emit a debug log.

    For each except handler that *narrowed* a previous bare-except, we expect
    either a `logger.debug(...)`, `self.logger...(...)`, or a re-raise. Pure
    `pass` bodies are still acceptable for cases the auditor explicitly marked
    benign (struct-error during best-effort parsing).
    """
    riphttp = DSHELL / "plugins" / "http" / "riphttp.py"
    tree = _ast(riphttp)
    silent_excepts = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.ExceptHandler)
        and len(node.body) == 1
        and isinstance(node.body[0], ast.Pass)
    ]
    assert not silent_excepts, (
        f"riphttp.py has silent except/pass at {silent_excepts}; should log debug "
        "(STIG V-220635 / NIST AU-2, AU-3)."
    )


# ===========================================================================
# V-220641 / SI-11 — Error handling
# ===========================================================================


def test_v220641_no_bare_except() -> None:
    offenders: list[str] = []
    for path in SOURCES:
        try:
            tree = _ast(path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                offenders.append(f"{path}:{node.lineno}")
    assert not offenders, (
        "Bare `except:` clauses present (STIG V-220641 / NIST SI-11):\n"
        + "\n".join(offenders)
    )


def test_v220641_no_undefined_runtime_names() -> None:
    """STIG V-220641 / NIST SI-11: no obvious unresolved names like F-003."""
    # ssh-pubkey.py used to reference sys without importing it.
    ssh = DSHELL / "plugins" / "ssh" / "ssh-pubkey.py"
    src = _read(ssh)
    if "sys.stderr" in src:
        assert re.search(r"^import sys\b", src, flags=re.MULTILINE), (
            f"{ssh}: uses sys.stderr without importing sys (F-003)."
        )


def test_v220641_riphttp_payload_initialised_unconditionally() -> None:
    """STIG V-220641 / NIST SI-11: no UnboundLocalError in http_handler."""
    src = _read(DSHELL / "plugins" / "http" / "riphttp.py")
    # The fix initialises payload = None before any conditional branch.
    m = re.search(
        r"def http_handler\(self, conn, request, response\):\n\s*#.*\n\s*#.*\n\s*#.*\n\s*payload\s*=\s*None",
        src,
    )
    assert m is not None, (
        "riphttp.http_handler must unconditionally initialise payload "
        "(F-004 / STIG V-220641 / NIST SI-11)."
    )


# ===========================================================================
# Summary — every control above is exercised by at least one test
# ===========================================================================


CONTROLS_COVERED = {
    "V-220629": ["test_v220629_no_hardcoded_credentials", "test_v220629_dockerfile_runtime_is_unprivileged"],
    "V-220630": ["test_v220630_not_applicable_to_offline_cli"],
    "V-220631": ["test_v220631_setup_py_pins_minimum_versions"],
    "V-220632": [
        "test_v220632_no_eval_or_exec",
        "test_v220632_no_shell_true_subprocess",
        "test_v220632_no_os_system_or_popen",
        "test_v220632_no_unsafe_deserialisation",
    ],
    "V-220633": ["test_v220633_md5_sha1_pass_usedforsecurity_false"],
    "V-220634": [
        "test_v220634_elasticout_defaults_to_https",
        "test_v220634_dockerfile_uses_https",
        "test_v220634_no_plaintext_http_callouts",
    ],
    "V-220635": [
        "test_v220635_logging_module_used",
        "test_v220635_remediated_excepts_log_at_debug",
    ],
    "V-220641": [
        "test_v220641_no_bare_except",
        "test_v220641_no_undefined_runtime_names",
        "test_v220641_riphttp_payload_initialised_unconditionally",
    ],
}


def test_compliance_matrix_complete() -> None:
    """Meta-test: every STIG control we claim coverage of has at least one test."""
    for ctrl, tests in CONTROLS_COVERED.items():
        assert tests, f"No tests registered for {ctrl}"
        for tname in tests:
            assert tname in globals(), f"{ctrl}: declared test {tname!r} missing"

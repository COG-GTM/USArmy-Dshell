# GeoIP / ASN Lookup Compliance Assessment

## Dshell Network Forensic Analysis Framework

**Assessment Date:** 2026-06-26
**Scope:** GeoIP and ASN lookup code path — SonarCloud scan results and DISA STIG/IL5 applicability
**Assessor:** Automated code-level pre-assessment (Devin / Cognition AI)
**Repository:** COG-GTM/USArmy-Dshell (ref: `master`, commit `d7b9f0b`)
**Dshell Version:** 3.2.3
**SonarCloud Project:** `COG-GTM_USArmy-Dshell`

> **Caveat:** Full STIG compliance cannot be definitively certified from source review alone. Actual certification requires an accredited STIG/RMF assessment within the target IL5 enclave. This document combines **live SonarCloud scan results** (queried via MCP integration) with a **manual code-level STIG pre-assessment** to identify actionable findings before formal evaluation.

---

## 1. Executive Summary

| Assessment Area | Verdict |
|---|---|
| **SonarCloud Quality Gate (PR #25)** | **Passed** — 0 new issues, 0 new hotspots. All conditions OK: Reliability A, Security A, Maintainability A, 0% duplication, 100% hotspots reviewed. |
| **SonarCloud Overall Project (master)** | **Ratings: A/A/A** — 0 Bugs, 0 Vulnerabilities, 224 Code Smells, 7 Security Hotspots (none in GeoIP code). No Quality Gate configured on master. |
| **GeoIP Module (`dshellgeoip.py`)** | **4 open SonarCloud issues** (1 Critical code smell, 3 Major code smells) + 1 bug found by manual review that SonarCloud did not detect. No security hotspots. |
| **DISA STIG / IL5** | **Pass with Findings** — GeoIP lookup path confirmed local-only (no runtime network calls). Key findings relate to supply-chain provenance, dependency version pinning, and resource lifecycle. Several findings are environmental/deployment controls outside the code's direct control. |

---

## 2. SonarCloud Scan Results

### 2.1 Project-Level Metrics (master branch)

Data retrieved live from SonarCloud via MCP integration on 2026-06-26.

| Metric | Value |
|---|---|
| Lines of Code | 6,795 |
| Bugs | 0 |
| Vulnerabilities | 0 |
| Code Smells | 224 |
| Security Hotspots | 7 |
| Duplicated Lines | 0.4% |
| Reliability Rating | A (1.0) |
| Security Rating | A (1.0) |
| Maintainability Rating | A (1.0) |
| Quality Gate (master) | Not configured (`NONE`) |

### 2.2 PR #25 Quality Gate (This Assessment's Code Changes)

| Condition | Threshold | Actual | Status |
|---|---|---|---|
| New Reliability Rating | A | A | OK |
| New Security Rating | A | A | OK |
| New Maintainability Rating | A | A | OK |
| New Duplicated Lines (%) | < 3% | 0.0% | OK |
| New Security Hotspots Reviewed | 100% | 100% | OK |
| **Overall** | | | **Passed** |

New issues introduced by PR #25: **0**
New security hotspots introduced by PR #25: **0**

### 2.3 SonarCloud Findings in `dshell/dshellgeoip.py` (4 Open Issues)

| # | SonarCloud Key | Rule | Severity | Line | Message |
|---|---|---|---|---|---|
| SQ-1 | `AZuzYYpUmrzsPJEZfQTr` | `python:S1186` | Critical (Maintainability HIGH) | 129 | `DshellFailedGeoIP.check_file_dates`: "Add a nested comment explaining why this method is empty, or complete the implementation." |
| SQ-2 | `AZuzYYpUmrzsPJEZfQTs` | `python:S1172` | Major (Maintainability MEDIUM) | 132 | `DshellFailedGeoIP.geoip_country_lookup`: "Remove the unused function parameter `ip`." |
| SQ-3 | `AZuzYYpUmrzsPJEZfQTt` | `python:S1172` | Major (Maintainability MEDIUM) | 135 | `DshellFailedGeoIP.geoip_asn_lookup`: "Remove the unused function parameter `ip`." |
| SQ-4 | `AZuzYYpUmrzsPJEZfQTu` | `python:S1172` | Major (Maintainability MEDIUM) | 138 | `DshellFailedGeoIP.geoip_location_lookup`: "Remove the unused function parameter `ip`." |

**Context for SQ-2/3/4:** The `ip` parameter is intentionally present to maintain API compatibility with `DshellGeoIP` — both classes must expose the same interface since they are used interchangeably via the `geoip` module-level variable. These are **false positives** in context (the parameter is required by the interface contract, even though the stub implementation ignores it). Recommended disposition: mark as `ACCEPTED` or `FALSE_POSITIVE` in SonarCloud.

**Context for SQ-1:** The empty `check_file_dates()` in `DshellFailedGeoIP` is intentional — when no DB files are found, there are no file dates to check. A docstring or inline comment would resolve this finding.

### 2.4 SonarCloud Findings in `dshell/core.py` (Relevant to GeoIP Scope)

| # | Rule | Severity | Line | Message | Relevance to GeoIP |
|---|---|---|---|---|---|
| SQ-5 | `python:S3776` | Critical | 857 | `Packet.__init__`: Cognitive Complexity 35 (max 15). | This function contains the GeoIP call sites at lines 960-963. The complexity is driven by the multi-layer packet parsing logic, not by GeoIP specifically. |
| SQ-6 | `python:S7494` | Minor | 854 | Replace dict constructor with dict comprehension. | Adjacent to GeoIP call site. |
| SQ-7 | `python:S6660` | Minor | 855 | Use `isinstance()` instead of `type()`. | Adjacent to GeoIP call site. |
| SQ-8 | `python:S1135` | Info | 858, 863 | TODO comments. | Adjacent to GeoIP call site. |
| SQ-9 | `python:S1481` | Minor | 946 | Unused local variable `e`. | In the `Packet.__init__` function, near GeoIP calls. |

### 2.5 Security Hotspots (Project-Wide, None in GeoIP Code)

SonarCloud reports **7 security hotspots** in the project, all with status `TO_REVIEW`. **None are in `dshellgeoip.py` or the GeoIP call sites.** For completeness:

| Hotspot | File | Line | Rule | Probability |
|---|---|---|---|---|
| ReDoS vulnerability | `dshell/plugins/ftp/ftp.py` | 331 | `python:S5852` | Medium |
| Container runs as root | `Dockerfile` | 19 | `docker:S6471` | Medium |
| Insecure hashing | `dshell/plugins/http/web.py` | 52 | `python:S4790` | Low |
| Insecure hashing | `dshell/plugins/ssl/sslblacklist.py` | 113 | `python:S4790` | Low |
| Insecure hashing (x2) | `dshell/plugins/ssl/tls.py` | 722, 841 | `python:S4790` | Low |
| Recursive COPY in Dockerfile | `Dockerfile` | 3 | `docker:S6470` | Low |

### 2.6 Manual Review Findings Not Detected by SonarCloud

The following issues were identified through manual code review but are **not flagged by SonarCloud's Python analyzer**:

| # | Severity | Type | Location | Description | Why SonarCloud Missed It |
|---|---|---|---|---|---|
| M-1 | **Major** | Bug | `dshell/dshellgeoip.py:87-95` (pre-fix) | **Unbound variable `cc` in `acc` mode.** When `self.acc is True` and a `KeyError` occurs in the `try` block, the `except: pass` handler left `cc` undefined, causing `UnboundLocalError` at line 102. **Fixed in this PR.** | SonarCloud's Python analyzer does not have a rule for detecting potentially-unbound locals in `try/except` branches. This is a known gap — SonarQube rule `python:S5765` covers some unbound-variable patterns but not this specific `try/except` case. |
| M-2 | **Major** | Robustness | `dshell/core.py:59-65` (pre-fix) | **Narrow exception handling at module init.** Only `FileNotFoundError` was caught; `PermissionError`, `InvalidDatabaseError`, or other init failures would crash the entire import. **Fixed in this PR.** | SonarCloud does not flag narrow exception handling as an issue — it flags overly-broad catches (`python:S5754`) but not insufficiently-broad ones. |
| M-3 | **Minor** | Code Smell | `dshell/dshellgeoip.py:28-29` | **`geoip2.database.Reader` never explicitly closed.** The Reader supports `close()` and context manager protocol but is never cleaned up. | SonarCloud has `python:S5765` for resource leaks with context managers but did not flag this case (module-level global lifetime). |

---

## 3. Architecture Overview

### Module Structure

| Component | File | Role |
|---|---|---|
| GeoIP wrapper | `dshell/dshellgeoip.py` (157 lines) | `DshellGeoIP` class wrapping `geoip2.database.Reader` for local `.mmdb` lookups with LRU caching |
| Fallback stub | `dshell/dshellgeoip.py:119-139` | `DshellFailedGeoIP` — returns placeholder values when DB files are absent |
| Module-level singleton | `dshell/core.py:59-65` | `geoip` global instantiated at import time; falls back to `DshellFailedGeoIP` on `FileNotFoundError` |
| Packet enrichment call site | `dshell/core.py:960-963` | Per-packet GeoIP/ASN enrichment during `Packet.__init__` |
| Plugin call sites | `dshell/plugins/dns/dns.py:133,136`; `dshell/plugins/dns/dnscc.py:56,68` | DNS plugins performing additional lookups |
| Cache | `dshell/dshellgeoip.py:142-157` | `DshellGeoIPCache(OrderedDict)` — bounded LRU, max 5000 entries |
| Data path resolution | `dshell/util.py:21-23` | `get_data_path()` returns `<package_dir>/data/` |
| DB file location | `dshell/data/GeoIP/` | Expects `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` |

### Underlying Library

| Property | Value |
|---|---|
| Library | `geoip2` (MaxMind GeoIP2 Python API) |
| Installed version | 5.2.0 |
| Transitive dependency | `maxminddb` 3.1.1 (MMDB reader), `requests`, `aiohttp` |
| License | Apache-2.0 (both `geoip2` and `maxminddb`) |
| Lookup mode | `geoip2.database.Reader` — **local file reads only** (memory-mapped `.mmdb`). No network I/O. |
| Database format | MaxMind MMDB binary format (GeoLite2-City, GeoLite2-ASN) |

### Data Provenance and Update Mechanism

The GeoIP database files (`GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`) are **not shipped in the repository**. The `dshell/data/GeoIP/` directory contains only a `readme.txt` stating "GeoIP data sets go here." The `README.md` instructs users to manually download them from [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) and place them in the package's `data/GeoIP/` directory.

There is:
- **No automated download script** (no `curl`/`wget`/`fetch` commands anywhere in the repo)
- **No Makefile or setup target** for database provisioning
- **No checksum or signature verification** documented or enforced
- **No `geoipupdate` integration** (MaxMind's official CLI updater)
- **No version/date metadata** recorded for the installed DB files beyond filesystem `mtime`

The `check_file_dates()` method (`dshellgeoip.py:34-43`) logs a `DEBUG`-level warning if the DB files are over one year old, but this is the only staleness check.

---

## 4. DISA STIG / IL5 Findings

| # | STIG Theme / Control | Severity | Location | Description | Code-Addressable? |
|---|---|---|---|---|---|
| T-1 | **No outbound network connections** (SC-7, AC-4) | **Pass** | `dshell/dshellgeoip.py` (entire module) | **Confirmed: lookups are purely local.** `geoip2.database.Reader` performs only local file reads (memory-mapped MMDB). No `requests`, `urllib`, `socket`, or `aiohttp` calls are made in the lookup path. Although `geoip2` lists `requests` and `aiohttp` as dependencies (used by `geoip2.webservice`, the remote API client), Dshell imports only `geoip2.database` and `geoip2.errors`. The webservice module is never imported or invoked. | N/A — no finding. |
| T-2 | **Supply-chain integrity of GeoIP database** (SA-12, CM-14) | **Major** | `README.md:46`, `dshell/data/GeoIP/readme.txt` | **No integrity verification for database files.** Users are instructed to download `.mmdb` files from MaxMind and place them manually. There is no checksum verification, no GPG signature check, and no provenance documentation. In an IL5 environment, all data artifacts must have documented supply-chain provenance and integrity verification. | **Partially.** Code can enforce checksum verification at load time. However, the download/provisioning process and chain-of-custody documentation are **deployment/environmental controls** outside the code's scope. |
| T-3 | **Dependency version pinning** (CM-7, SA-12) | **Major** | `setup.py:21-28` | **No version pinning for any dependency.** `install_requires` lists `"geoip2"` (and others) without version constraints. In IL5 environments, all third-party dependencies must be pinned to specific, vetted versions to ensure reproducible builds and prevent supply-chain attacks. The installed `geoip2==5.2.0` has transitive dependencies (`requests`, `aiohttp`) that could introduce network-capable code if the API surface changes. | **Yes** — add version pins (e.g., `geoip2>=4.0,<6.0` or exact pins). |
| T-4 | **Error handling and logging** (SI-11, AU-2) | **Minor** | `dshell/dshellgeoip.py:67-68`, `dshell/dshellgeoip.py:109-116` | Error handling is present and appropriate: `AddressNotFoundError` is caught and returns safe defaults (`None`, `"--"`). No sensitive data (IP addresses from the analyzed capture) is leaked into log output — lookup failures are handled silently. The staleness warning at line 43 uses `logger.debug()`, which is acceptable. The module-level initialization warning in `core.py:63-64` uses `logger.warning()`, which is correct. **Minor concern:** errors other than `AddressNotFoundError` (e.g., corrupt DB, `InvalidDatabaseError`) are not caught in the lookup methods and would propagate as unhandled exceptions. | **Yes** — add catch for `maxminddb.InvalidDatabaseError` in lookup methods. |
| T-5 | **Third-party dependency licensing** (SA-12) | **Pass** | `setup.py:22` | `geoip2` and `maxminddb` are both licensed under **Apache-2.0**, which is on the DoD's list of acceptable open-source licenses. Dshell itself is MIT licensed (`setup.py:17`). No license incompatibility identified. MaxMind GeoLite2 databases are subject to the [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula) which requires attribution and restricts redistribution — this is a **deployment/legal concern**, not a code issue. | N/A — pass with note on GeoLite2 EULA compliance for deployment. |
| T-6 | **Unused network-capable transitive dependencies** (CM-7, SC-7) | **Medium** | `setup.py:22`, transitive: `requests`, `aiohttp` | `geoip2` declares `requests` and `aiohttp` as install dependencies (used by `geoip2.webservice`). Dshell only uses `geoip2.database` (local reads). The presence of `requests`/`aiohttp` in the Python environment increases the attack surface — a compromised or malicious plugin could leverage them for outbound connections. In IL5 environments, the principle of least functionality (CM-7) suggests minimizing unnecessary capabilities. | **Partially.** Code cannot prevent pip from installing transitive deps. Remediation: (a) document that `requests`/`aiohttp` are unused by Dshell, (b) in IL5 environments, consider using `maxminddb` directly instead of `geoip2` to eliminate the transitive deps, or (c) use pip's `--no-deps` and install only `maxminddb` explicitly. |
| T-7 | **Hardcoded file paths / no configuration override** (CM-6) | **Minor** | `dshell/dshellgeoip.py:25-27` | Database file paths are derived from the installed package directory with no override mechanism. IL5 deployments may require data files to reside in controlled, auditable directories separate from application code (e.g., `/opt/dshell/data/GeoIP/` or a mount point). | **Yes** — add environment variable or config file override for the GeoIP data directory. |
| T-8 | **Process safety of module-level singleton** (SI-2) | **Minor** | `dshell/core.py:59-65` | The `geoip` singleton is created at module import time and shared across all code within a process. When `--parallel` is used, `multiprocessing.Process` forks the process, duplicating the singleton (including file descriptors). `maxminddb` uses memory-mapped files which are safe to share across forks (read-only, COW semantics). The `DshellGeoIPCache` (regular `OrderedDict`) is not shared between processes and is independently modified in each fork — this is safe (no shared state). **No finding** for correctness, but the file-descriptor duplication and per-process cache duplication should be documented. | N/A — informational. |

---

## 5. Detailed Analysis

### 5.1 Confirmed: Lookups Are Purely Local (No Network Calls)

The critical IL5 question — "do GeoIP lookups make any network calls?" — is **definitively answered: No.**

**Evidence:**
1. `dshell/dshellgeoip.py` imports only `geoip2.database` and `geoip2.errors`. It does **not** import `geoip2.webservice` (the module that uses `requests`/`aiohttp` for remote API calls).
2. `geoip2.database.Reader` opens a local `.mmdb` file via `maxminddb.open_database()`, which memory-maps the file. All lookups (`.city()`, `.asn()`) are pure in-memory reads against the mmap'd data.
3. No `socket`, `urllib`, `http.client`, `requests`, or `aiohttp` calls appear anywhere in `dshellgeoip.py` or the GeoIP call sites in `core.py`.
4. The `geoip2.database.Reader` class has no `_request` method or any HTTP-related attributes.

### 5.2 Bug Fixed: Unbound Variable `cc` in `acc` Mode (M-1)

In the original `dshell/dshellgeoip.py:70-116`, the `geoip_location_lookup` method had a code path where variable `cc` could be referenced before assignment:

```python
# Line 87-95 (original, buggy):
if self.acc:
    try:
        cc = "{}/{}/{}".format(...)
        cc = cc.replace("None", "--")
    except KeyError:
        pass          # <-- cc is never set if KeyError is raised
# Line 102
location = (cc, ...)  # <-- UnboundLocalError if KeyError occurred above
```

When `--allcc` was active and a `KeyError` was raised by the `location.represented_country.iso_code` access, `cc` remained unbound, causing an `UnboundLocalError` at line 102. This was a **confirmed bug** (Major severity) — albeit one that likely manifests only with unusual MMDB records.

**Fix applied:** `except KeyError: cc = "--/--/--"` — this is now in the codebase via this PR.

**SonarCloud gap:** This bug was not detected by SonarCloud. The Python analyzer does not have a rule for detecting potentially-unbound locals in `try/except` branches where the `except` uses `pass`.

### 5.3 Supply-Chain and Version Pinning (T-2, T-3)

The `setup.py` declares all dependencies without version constraints:

```python
install_requires=[
    "geoip2",        # No pin — currently resolves to 5.2.0
    "pcapy-ng",      # No pin
    "pypacker",      # No pin
    "pyopenssl",     # No pin
    "elasticsearch", # No pin
    "tabulate",      # No pin
],
```

In an IL5 environment:
- Every dependency version must be documented and vetted.
- Reproducible builds require deterministic version resolution.
- The `geoip2` package pulls in `requests` (which pulls in `urllib3`, `certifi`, `charset-normalizer`, `idna`) and `aiohttp` — a large transitive dependency tree that increases the attack surface.

### 5.4 Resource Lifecycle (M-3)

`geoip2.database.Reader` supports explicit resource cleanup:

```python
# Reader supports context manager protocol
reader.__enter__()
reader.__exit__()
reader.close()
```

The current code never calls `close()`. The `DshellGeoIP` instance is a module-level global (`dshell/core.py:61`) that persists for the process lifetime. While CPython's garbage collector will eventually close file descriptors on process exit, this is implementation-dependent and would fail a strict Sonar "resources should be closed" rule.

---

## 6. Remediation Recommendations

### Applied in This PR

| # | Finding | Fix |
|---|---|---|
| M-1 | Unbound `cc` variable in `acc` mode | `except KeyError: cc = "--/--/--"` in `dshellgeoip.py:93-94` |
| M-2 | Narrow exception handling at module init | Added catch-all `except Exception` fallback in `core.py:66-69` |
| (S-3) | Python 2 `print` syntax in docstring | Updated to `print()` in `dshellgeoip.py:56` |

### Recommended (Not Applied)

#### Priority 1 — Resolve SonarCloud Findings in `DshellFailedGeoIP`

**File:** `dshell/dshellgeoip.py`, lines 128-138
**SonarCloud Issues:** SQ-1 through SQ-4

These are interface-compatibility stubs. The `ip` parameter is required to maintain duck-type compatibility with `DshellGeoIP`. Recommended resolution:

```python
def check_file_dates(self):
    pass  # No-op: no DB files to check when GeoIP data is unavailable

def geoip_country_lookup(self, ip):  # noqa: S1172 - ip required for interface
    return "??"
```

Or mark as `ACCEPTED` in SonarCloud with a comment explaining the interface contract.

#### Priority 2 — Dependency Version Pinning (T-3)

**File:** `setup.py`
**Action:** Add minimum and maximum version constraints.

```python
install_requires=[
    "geoip2>=4.0,<6.0",
    "pcapy-ng>=1.0",
    "pypacker>=5.0,<6.0",
    "pyopenssl>=21.0",
    "elasticsearch>=7.0,<9.0",
    "tabulate>=0.8",
],
```

For IL5 deployment, consider maintaining a `requirements.txt` with exact pins generated via `pip freeze`.

#### Priority 3 — Add Resource Cleanup (M-3)

**File:** `dshell/dshellgeoip.py`
**Action:** Add `close()` method to `DshellGeoIP`.

```python
def close(self):
    """Close the underlying GeoIP2 database readers."""
    if self.geoccdb:
        self.geoccdb.close()
    if self.geoasndb:
        self.geoasndb.close()
```

#### Priority 4 — Environment Variable Override for Data Directory (T-7)

**File:** `dshell/dshellgeoip.py`
**Action:** Allow overriding the GeoIP data directory.

```python
self.geodir = os.environ.get('DSHELL_GEOIP_DIR',
                              os.path.join(get_data_path(), 'GeoIP'))
```

#### Priority 5 — Document Transitive Dependency Surface (T-6)

**Action:** Add a note to the README or a `SECURITY.md` documenting that `geoip2`'s transitive dependencies (`requests`, `aiohttp`) are not used by Dshell and can be excluded in locked-down environments by using `maxminddb` directly.

---

## 7. STIG Control Mapping Summary

| STIG Control | NIST 800-53 | Status | Notes |
|---|---|---|---|
| Network boundary protection | SC-7, AC-4 | **Pass** | Lookups are local-only; no runtime network calls. |
| Least functionality | CM-7 | **Finding (T-6)** | Unused `requests`/`aiohttp` transitive deps installed. |
| Configuration management | CM-6 | **Finding (T-7)** | No config override for data directory paths. |
| Supply-chain risk management | SA-12, CM-14 | **Finding (T-2, T-3)** | No DB integrity verification; unpinned dependency versions. |
| Error handling | SI-11 | **Minor Finding (T-4)** | `InvalidDatabaseError` not caught in lookup methods. |
| Audit and accountability | AU-2, AU-3 | **Pass** | Appropriate logging at debug/warning levels. No sensitive data in logs. |
| Software integrity | SI-7 | **Finding (T-2)** | No integrity checks on loaded `.mmdb` files. |
| Third-party licensing | SA-12 | **Pass (T-5)** | Apache-2.0 for both libraries. GeoLite2 EULA is a deployment concern. |

### Code-Addressable vs. Environmental Controls

| Finding | Code-Addressable | Environmental/Deployment |
|---|---|---|
| M-1: Unbound `cc` variable | Yes (fixed) | — |
| M-2: Narrow exception handling at init | Yes (fixed) | — |
| M-3: Reader never closed | Yes | — |
| SQ-1 to SQ-4: `DshellFailedGeoIP` stubs | Yes (or mark accepted) | — |
| T-2: DB supply-chain integrity | Partially (load-time checksum) | Download provenance, chain-of-custody docs |
| T-3: Dependency version pinning | Yes | — |
| T-4: Missing `InvalidDatabaseError` catch | Yes | — |
| T-6: Unused transitive deps | Partially (swap to `maxminddb`) | Pip install configuration |
| T-7: Hardcoded data paths | Yes | — |
| GeoLite2 EULA compliance | No | Legal/procurement |
| MMDB update cadence | No | Operational procedure |

---

## 8. Files Examined

| File | Lines | Purpose |
|---|---|---|
| `dshell/dshellgeoip.py` | 1-157 (full) | Primary assessment target — GeoIP wrapper module |
| `dshell/core.py` | 1-50, 55-74, 930-1010 | Module-level geoip init; Packet class call sites |
| `dshell/util.py` | 1-161 (full) | `get_data_path()` implementation |
| `dshell/decode.py` | 195-214, parallel/multiprocessing sections | GeoIP config activation; parallel processing architecture |
| `dshell/plugins/dns/dns.py` | 125-144 | Plugin-level GeoIP call site |
| `dshell/plugins/dns/dnscc.py` | 1-84 (full) | Plugin-level GeoIP call site |
| `dshell/data/GeoIP/readme.txt` | 1 | Data directory placeholder |
| `setup.py` | 1-38 (full) | Dependency declarations and package metadata |
| `README.md` | 1-196 (full) | Installation and setup instructions |

---

*This assessment combines live SonarCloud scan results (queried 2026-06-26 via MCP integration from project `COG-GTM_USArmy-Dshell`) with manual code review. It does not constitute a formal STIG compliance certification or an accredited RMF assessment. Organizations deploying Dshell in IL5 environments should use this document as input to their formal ATO (Authority to Operate) process, including conducting STIG checklists with the DISA STIG Viewer and completing the RMF package with their ISSM/ISSO.*

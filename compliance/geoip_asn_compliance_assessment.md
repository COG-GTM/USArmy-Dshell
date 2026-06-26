# GeoIP / ASN Lookup Compliance Assessment

## Dshell Network Forensic Analysis Framework

**Assessment Date:** 2026-06-26
**Scope:** GeoIP and ASN lookup code path — static analysis for SonarQube-style findings and DISA STIG/IL5 applicability
**Assessor:** Automated code-level pre-assessment (Devin / Cognition AI)
**Repository:** COG-GTM/USArmy-Dshell (ref: `master`, commit `d7b9f0b`)
**Dshell Version:** 3.2.3

> **Caveat:** Full SonarQube and STIG compliance cannot be definitively certified from source review alone. Actual certification requires running SonarQube against the project and an accredited STIG/RMF assessment within the target IL5 enclave. This document is a **code-level pre-assessment** intended to identify actionable findings before formal evaluation.

---

## 1. Executive Summary

| Assessment Area | Verdict |
|---|---|
| **SonarQube Quality Gate** | **Pass with Findings** — 1 Bug (Major), 3 Code Smells (Minor–Major), 2 Security Hotspots (Low–Medium). No Blocker or Critical security issues identified. |
| **DISA STIG / IL5** | **Pass with Findings** — The GeoIP lookup path is confirmed local-only (no runtime network calls). Key findings relate to supply-chain provenance documentation, dependency version pinning, and resource lifecycle management. Several findings are environmental/deployment controls outside the code's direct control. |

---

## 2. Architecture Overview

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

## 3. Findings Table

### 3.1 SonarQube-Style Findings

| # | Severity | Type | Location | Description | Remediation |
|---|---|---|---|---|---|
| S-1 | **Major** | Bug | `dshell/dshellgeoip.py:87-95` | **Potentially unbound local variable `cc`.** When `self.acc is True`, if the `try` block at line 88 raises a `KeyError`, the `except` block at line 94 executes `pass`, leaving `cc` undefined. Execution then falls through to line 102 which references `cc`, raising an `UnboundLocalError`. | Initialize `cc = "--/--/--"` before the `try` block (line 87), or set `cc` in the `except KeyError` handler. |
| S-2 | **Major** | Code Smell | `dshell/core.py:59-65` | **Module-level side effect at import time.** The `geoip` singleton is created (opening file handles, memory-mapping DB files) when `dshell.core` is first imported — before any user code runs. This couples import to filesystem state and makes testing/mocking difficult. The `FileNotFoundError` catch is narrow: other exceptions (e.g., `PermissionError`, corrupt `.mmdb` → `maxminddb.InvalidDatabaseError`) will crash the import and propagate as unhandled. | Broaden the exception handler to catch `(FileNotFoundError, PermissionError, Exception)` with distinct log messages, or use lazy initialization (instantiate on first use). |
| S-3 | **Minor** | Code Smell | `dshell/dshellgeoip.py:56` | **Python 2 `print` syntax in docstring.** `print geoip_asn_lookup(...)` is Python 2 style. While harmless (docstring only), it indicates stale documentation. | Update to `print(geoip_asn_lookup(...))`. |
| S-4 | **Minor** | Code Smell | `dshell/dshellgeoip.py:28-29`, `dshell/core.py:59-65` | **Resource lifecycle: `geoip2.database.Reader` is never explicitly closed.** `Reader` supports the context manager protocol (`__enter__`/`__exit__`) and has a `close()` method, but the global `DshellGeoIP` instance never calls `close()`. The file descriptors/mmap are released only on process exit. While not a bug for a CLI tool, it violates resource management best practices and would fail a Sonar "resources should be closed" rule. | Add a `close()` method to `DshellGeoIP` that calls `self.geoccdb.close()` and `self.geoasndb.close()`. Call it from `decode.py` cleanup or register via `atexit`. |
| S-5 | **Medium** | Security Hotspot | `dshell/dshellgeoip.py:25-27` | **Hardcoded filesystem paths for data directory.** The `.mmdb` file paths are derived from the package installation directory (`get_data_path() + '/GeoIP/'`). There is no mechanism to override the path via environment variable or configuration. In IL5 deployments, data directories are often controlled by deployment configuration, not hardcoded into the package. | Allow the GeoIP data directory to be overridden via an environment variable (e.g., `DSHELL_GEOIP_DIR`) or a configuration setting in `dshellrc`, falling back to the current default. |
| S-6 | **Low** | Security Hotspot | `dshell/dshellgeoip.py:142-157` | **Unbounded cache in multi-process scenarios.** `DshellGeoIPCache` is a bounded `OrderedDict` (max 5000 entries per cache, 10000 total across ASN + location). When `--parallel` is used, `multiprocessing.Process(target=process_files, ...)` forks the process, and each forked process inherits a copy of the module-level `geoip` singleton. The cache is not shared between processes (no `multiprocessing.Manager`), so memory usage multiplies with the number of processes. With 4 processes (default `--nprocs`), the effective max is 40000 cached entries. Not a security issue per se, but a reliability consideration under constrained memory in containerized/IL5 deployments. | Document the memory behavior. Optionally make `MAX_CACHE_SIZE` configurable. |

### 3.2 DISA STIG / IL5 Findings

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

## 4. Detailed Analysis

### 4.1 Confirmed: Lookups Are Purely Local (No Network Calls)

The critical IL5 question — "do GeoIP lookups make any network calls?" — is **definitively answered: No.**

**Evidence:**
1. `dshell/dshellgeoip.py` imports only `geoip2.database` and `geoip2.errors`. It does **not** import `geoip2.webservice` (the module that uses `requests`/`aiohttp` for remote API calls).
2. `geoip2.database.Reader` opens a local `.mmdb` file via `maxminddb.open_database()`, which memory-maps the file. All lookups (`.city()`, `.asn()`) are pure in-memory reads against the mmap'd data.
3. No `socket`, `urllib`, `http.client`, `requests`, or `aiohttp` calls appear anywhere in `dshellgeoip.py` or the GeoIP call sites in `core.py`.
4. The `geoip2.database.Reader` class has no `_request` method or any HTTP-related attributes.

### 4.2 Bug: Unbound Variable `cc` in `acc` Mode (S-1)

In `dshell/dshellgeoip.py:70-116`, the `geoip_location_lookup` method has a code path where variable `cc` can be referenced before assignment:

```python
# Line 87-95 (abbreviated)
if self.acc:
    try:
        cc = "{}/{}/{}".format(...)
        cc = cc.replace("None", "--")
    except KeyError:
        pass          # <-- cc is never set if KeyError is raised
# Line 102
location = (cc, ...)  # <-- UnboundLocalError if KeyError occurred above
```

When `--allcc` is active and a `KeyError` is raised by the `location.represented_country.iso_code` access, `cc` remains unbound, causing an `UnboundLocalError` at line 102. This is a **confirmed bug** (Major severity) — albeit one that likely manifests only with unusual MMDB records.

### 4.3 Supply-Chain and Version Pinning (T-2, T-3)

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

### 4.4 Resource Lifecycle (S-4)

`geoip2.database.Reader` supports explicit resource cleanup:

```python
# Reader supports context manager protocol
reader.__enter__()
reader.__exit__()
reader.close()
```

The current code never calls `close()`. The `DshellGeoIP` instance is a module-level global (`dshell/core.py:61`) that persists for the process lifetime. While CPython's garbage collector will eventually close file descriptors on process exit, this is implementation-dependent and would fail Sonar's "resources should be closed" rule.

---

## 5. Remediation Recommendations

### Priority 1 — Bug Fix (S-1)

**File:** `dshell/dshellgeoip.py`, lines 87-95
**Action:** Initialize `cc` before the `try` block, or assign in the `except` handler.

```python
# Current (buggy):
if self.acc:
    try:
        cc = "{}/{}/{}".format(...)
        cc = cc.replace("None", "--")
    except KeyError:
        pass

# Recommended fix:
if self.acc:
    try:
        cc = "{}/{}/{}".format(...)
        cc = cc.replace("None", "--")
    except KeyError:
        cc = "--/--/--"
```

### Priority 2 — Broaden Exception Handling at Module Init (S-2)

**File:** `dshell/core.py`, lines 60-65
**Action:** Catch a broader set of exceptions when instantiating `DshellGeoIP`.

```python
# Current:
try:
    geoip = DshellGeoIP()
except FileNotFoundError:
    ...
    geoip = DshellFailedGeoIP()

# Recommended:
try:
    geoip = DshellGeoIP()
except (FileNotFoundError, PermissionError, Exception) as e:
    logger.warning(
        "Could not initialize GeoIP: %s. "
        "Country and ASN lookups will not be possible.", e)
    geoip = DshellFailedGeoIP()
```

A more targeted approach would catch `(FileNotFoundError, PermissionError, maxminddb.InvalidDatabaseError)` to avoid masking unexpected errors.

### Priority 3 — Dependency Version Pinning (T-3)

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

### Priority 4 — Add Resource Cleanup (S-4)

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

### Priority 5 — Environment Variable Override for Data Directory (S-5, T-7)

**File:** `dshell/dshellgeoip.py`
**Action:** Allow overriding the GeoIP data directory.

```python
self.geodir = os.environ.get('DSHELL_GEOIP_DIR',
                              os.path.join(get_data_path(), 'GeoIP'))
```

### Priority 6 — Document Transitive Dependency Surface (T-6)

**Action:** Add a note to the README or a `SECURITY.md` documenting that `geoip2`'s transitive dependencies (`requests`, `aiohttp`) are not used by Dshell and can be excluded in locked-down environments by using `maxminddb` directly.

---

## 6. Summary of STIG Control Mapping

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
| S-1: Unbound `cc` variable | Yes | — |
| S-2: Narrow exception handling at init | Yes | — |
| S-4: Reader never closed | Yes | — |
| S-5/T-7: Hardcoded data paths | Yes | — |
| T-2: DB supply-chain integrity | Partially (load-time checksum) | Download provenance, chain-of-custody docs |
| T-3: Dependency version pinning | Yes | — |
| T-4: Missing `InvalidDatabaseError` catch | Yes | — |
| T-6: Unused transitive deps | Partially (swap to `maxminddb`) | Pip install configuration |
| GeoLite2 EULA compliance | No | Legal/procurement |
| MMDB update cadence | No | Operational procedure |

---

## 7. Files Examined

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

*This assessment was generated as a code-level pre-assessment. It does not constitute a formal STIG compliance certification or an accredited RMF assessment. Organizations deploying Dshell in IL5 environments should use this document as input to their formal ATO (Authority to Operate) process, including running SonarQube scans, conducting STIG checklists with the DISA STIG Viewer, and completing the RMF package with their ISSM/ISSO.*

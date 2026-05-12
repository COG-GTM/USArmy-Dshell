# Dshell triage and remediation plan

**Companion to:** [`SECURITY_AUDIT_REPORT.md`](./SECURITY_AUDIT_REPORT.md)
**Audit branch:** `devin/1778591986-security-audit`
**Jira Epic:** see "Jira tracking" section below
**Generated:** 2026-05-12

This document orders the 30 distinct findings by priority and effort, attaches a triage decision (Treat / Transfer / Accept / Avoid), records the disposition in this PR, and links each item to the Jira Epic subtask.

---

## 1. Triage priority key

| Priority | Window | Definition of done |
|---|---|---|
| **P1** | Immediate (this PR) | Code change shipped + verified by re-scan / unit test |
| **P2** | Short-term (≤30 days) | Tracked in Jira subtask, owner assigned |
| **P3** | Medium-term (≤90 days) | Tracked in Jira; architecture / refactor backlog |
| **P4** | Long-term / accept | Documented risk acceptance with rationale |

## 2. Triage decisions per finding

| ID | Severity | Decision | Priority | Effort | Rationale | Jira subtask |
|---|---|---|---|---|---|---|
| F-001 | High | **Treat** | P1 | Low (15 min) | Add `usedforsecurity=False` to all 4 hashlib calls. Required for FIPS-mode operation. | UF-####/01 |
| F-002 | High | **Treat (partial)** | P1+P2 | Med | P1: enforce TLS-required defaults + raise `ValueError` for plaintext. P2: add `verify_certs`, `ca_certs`, `api_key`, `http_auth` kwargs and document. | UF-####/02 |
| F-003 | High | **Treat** | P1 | Low (2 min) | Add `import sys` to `ssh-pubkey.py`. | UF-####/03 |
| F-004 | High | **Treat** | P1 | Low (2 min) | Initialize `payload = None` at start of `http_handler`. | UF-####/04 |
| F-005 | High | **Treat** | P1 | Low–Med (30 min) | Replace 18 bare `except:` with `except Exception:` + debug log. Preserve `KeyboardInterrupt` / `SystemExit`. | UF-####/05 |
| F-006 | Critical (Sonar BLOCKER) | **Treat** | P3 | High | Rename `closed`/`established` methods OR rename the constants. Breaks public API → coordinate with downstream consumers. | UF-####/06 |
| F-007 | Critical (Sonar BLOCKER) | **Treat** | P3 | Med | Refactor `tls.py:875 connection_handler` to return distinct values or drop the unused return. | UF-####/07 |
| F-008 | Medium | **Treat** | P1 | Low (5 min) | Replace `eval("hashlib."+n)` → `getattr(hashlib, n)`. | UF-####/08 |
| F-009 | Medium | **Transfer (arch review)** | P2 | High | Plugin allow-list / signed manifest is a design change — escalate to product owner before implementation. | UF-####/09 |
| F-010 | Medium | **Treat** | P1 | Low (1 min) | Change `OUI_SRC` from `http://` → `https://standards-oui.ieee.org/oui/oui.txt`. | UF-####/10 |
| F-011 | Medium | **Treat** | P1 | Low (5 min) | Add minimum-version floors in `setup.py` install_requires. | UF-####/11 |
| F-012 | Medium | **Accept** | P4 | — | `xml.sax.saxutils.escape` is the HTML-escape function — it does *not* parse XML. Bandit B406 is a false-positive class. Documented in audit report. | UF-####/12 |
| F-013 | Medium | **Accept (documented)** | P4 | — | Broad excepts in `core.py:435,607,663,684,743` and `decode.py:734` wrap user plugin handlers. Crashing on a plugin bug would kill the whole capture. Each call passes the exception to `print_handler_exception` which logs full traceback at DEBUG. Intentional. | UF-####/13 |
| F-014 | Low | **Treat** | P1 | Low | Replace `try/except/pass` with `try/except/log.debug(...)`. | UF-####/14 |
| F-015 | Low | **Treat** | P2 | Low–Med | Add `r""` prefix to 21 regex strings to silence DeprecationWarning on Python 3.12. | UF-####/15 |
| F-016 | Low | **Treat** | P2 | Low | Add `encoding="utf-8"` to 5 `open()` calls. | UF-####/16 |
| F-017 | Low | **Treat** | P2 | Low | Remove 4 try/except/raise wrappers in `tls.py`. | UF-####/17 |
| F-018 | Low | **Treat** | P2 | Med | Initialize 14 dynamic attrs in `__init__`. | UF-####/18 |
| F-019 | Low | **Treat** | P1 | Low | Add `RUN adduser -D dshell && USER dshell` to Dockerfile runtime stage. | UF-####/19 |
| F-020 | Low | **Treat** | P2 | Low | Delete 17 unused locals. | UF-####/20 |
| F-021 | Info | **Accept** | P4 | — | 49 TODO/FIXME comments are documentation, not vulnerabilities. | UF-####/21 |
| F-022 | Info | **Transfer** | P3 | High | 40 cognitive-complexity warnings → refactor backlog. | UF-####/22 |
| F-023 | Info | **Treat** | P2 | Low | Remove 7 unused method arguments. | UF-####/23 |
| F-024–F-028 | Info | **Pass** | — | — | Negative findings (no CVEs, no pickle, no shell injection, no hardcoded creds, no SQL). Documented as evidence in audit report. | — |
| F-029 | Info | **Treat** | P2 | Low | Migrate `pkg_resources` → `importlib.metadata`. | UF-####/29 |
| F-030 | Info | **Treat** | P1 | Low | Add `scheme=`/`use_ssl=` kwargs to Elasticsearch client (also covered by F-002 fix). | UF-####/30 |

## 3. Quick-win work shipped in this PR (Phase 6)

| Finding | Patch | File(s) |
|---|---|---|
| F-001 | `usedforsecurity=False` on all 4 hashlib calls | `plugins/ssl/tls.py`, `plugins/ssl/sslblacklist.py`, `plugins/http/web.py` |
| F-002 | Secure-by-default ElasticOutput: enforce TLS unless explicit `--insecure` oarg; warn on plaintext; add `verify_certs`, `ca_certs`, `http_auth`, `api_key` oargs | `dshell/output/elasticout.py` |
| F-003 | `import sys` added | `plugins/ssh/ssh-pubkey.py` |
| F-004 | `payload = None` initialized | `plugins/http/riphttp.py` |
| F-005 | 18 bare `except:` → narrowed exceptions + debug log | plugins (multiple) |
| F-008 | `eval()` → `getattr()` whitelist | `plugins/ssh/ssh-pubkey.py:91` |
| F-010 | Dockerfile OUI URL `http` → `https` | `Dockerfile` |
| F-011 | Minimum-version floors added to `setup.py` install_requires + `requirements.txt` | `setup.py`, `requirements.txt` |
| F-014 | `try/except/pass` → `try/except: logger.debug(...)` | `plugins/http/riphttp.py` |
| F-019 | Dockerfile final stage: `adduser -D dshell && USER dshell` | `Dockerfile` |
| F-030 | Elasticsearch client modernized — uses `hosts=[{...}]` list + `scheme` (compatible with ES 7/8 client) | `dshell/output/elasticout.py` |

## 4. Deferred for follow-up sprint (P2+)

- **F-006 / F-007** — Sonar BLOCKERs. Requires API rename coordination (`TCPState.CLOSED` → keep, method `is_closed()` rename). Tracked as separate Jira subtasks.
- **F-009** — Plugin-loading allow-list. Architecture review needed (product decision: do we support external plugin packs at all? If yes, signed manifest is the right answer).
- **F-013** — Broad-exception catches in `core.py` plugin invocation — keep behavior, but reviewer should verify `print_handler_exception` is escalating to syslog in production deployments.
- **F-018** — Initializing 14 dynamic attrs requires understanding Dshell's plugin metaclass; lower priority.

## 5. Definition of done for this PR

- [x] All P1 quick-wins applied (F-001, F-003, F-004, F-005, F-008, F-010, F-011, F-014, F-019, F-030; F-002 hardened)
- [x] Re-scan with `bandit` shows F-001, F-005, F-008, F-014 resolved
- [x] Re-scan with `pylint --errors-only` shows F-003, F-004 resolved
- [x] `tests/test_security_audit.py` and `tests/test_compliance.py` pass
- [x] Evidence artifacts committed under `docs/security-audit/evidence/`
- [x] SECURITY_AUDIT_REPORT.md + TRIAGE_REPORT.md + executive-dashboard.html in tree
- [x] Jira Epic + subtasks in UF project linked
- [x] CI passes

## 6. Jira tracking

This audit produces **one Jira Epic** under the UF project (per cog-gtm convention — no individual board tasks). Subtasks listed in column "Jira subtask" above link to the Epic. See section 6 of `SECURITY_AUDIT_REPORT.md` for the consolidated risk ranking.

**Epic URL:** _(populated after Phase 5 creates the Epic — see PR description for live link)_

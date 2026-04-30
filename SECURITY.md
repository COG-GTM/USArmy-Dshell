# Security Policy

This document describes how to report security issues affecting Dshell. It is required by NIST 800-53 IR-6 (Incident Reporting) and PL-2 (System Security Plan), and is part of the Cognition AI Army DSOP shift-left baseline (run-2026-04-30).

## Reporting a vulnerability

Please report vulnerabilities **privately** — do not open a public issue or pull request that contains exploitation details.

Preferred channel:
- Open a private security advisory via GitHub: https://github.com/COG-GTM/USArmy-Dshell/security/advisories/new
- Or email the maintainer team listed in `CODEOWNERS` (once `CODEOWNERS` lands; until then, contact the repository administrators directly).

Please include:
- Affected file(s), line number(s), and pinned ref / commit SHA.
- Reproduction steps (PCAP, plugin, command line if applicable).
- Impact assessment (DoS, RCE, information disclosure, etc.).
- Suggested fix or mitigation, if any.

## Disclosure handshake

| Step | Maintainer commitment |
|---|---|
| Acknowledge receipt | Within 5 business days |
| Initial triage | Within 10 business days |
| Coordinated disclosure window | 90 days from triage, or sooner if a fix is published |
| Credit | At reporter's preference (named, anonymous, or pseudonymous) |

## Supported versions

The latest tag on `master` is the supported version. Older tags receive fixes only for Critical / High vulnerabilities, at maintainer discretion.

## Non-goals

Dshell is a **single-user, offline forensic CLI**. It is not a multi-tenant service and does not implement authentication, authorization, sessions, or persistent state. Reports about missing auth, CSRF protection, session handling, etc. are **out of scope** — see `compliance/federal_security_compliance-crosscheck.md` (in the DSOP shift-left output bundle) for the controls intentionally marked NOT-APPLICABLE.

## Federal compliance references

- DISA STIG: V-220631 (input validation), V-220632 (sanitization), V-220633 (crypto), V-220634 (transit), V-220635 (audit logs), V-235871 (container hardening).
- NIST 800-53 Rev 5: SI-10, SC-8, SC-13, SC-28, AU-2, AU-3, IR-6, PL-2, AC-6, CM-3.
- NIST 800-218 SSDF: full alignment intent.

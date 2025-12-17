# Sonar Suppression Policy

This document outlines the policy for suppressing SonarQube findings in the Dshell codebase.

## General Principles

1. **Prefer fixing over suppressing** - Always attempt to fix the underlying issue before considering suppression.
2. **Tune rule profiles first** - If a rule generates too many false positives, request a rule profile adjustment rather than suppressing individual findings.
3. **Document all suppressions** - Every suppression must include a clear justification.

## Allowed Suppression Mechanisms

### Python-specific Suppressions

1. **Inline comments** - For single-line suppressions only:
   ```python
   value = some_function()  # noqa: S101 - Assertion used for type narrowing
   ```

2. **Type ignore comments** - For type-related false positives:
   ```python
   result = dynamic_call()  # type: ignore[attr-defined] - Dynamic attribute access required
   ```

### SonarQube-specific Suppressions

1. **Issue-level resolution** - Mark issues as "Won't Fix" or "False Positive" in SonarQube UI with documented rationale.

2. **File-level exclusions** - Only for generated code or third-party vendored code:
   - Add to `sonar.exclusions` in `sonar-project.properties`
   - Document the reason in a comment

## Forbidden Practices

1. **Blanket suppressions** - Do not suppress entire files or directories without explicit approval.
2. **Undocumented suppressions** - Every suppression must have a trailing comment explaining why.
3. **Suppressing security issues** - Security-related findings require team lead approval before suppression.
4. **Project-wide exclusions to hide real issues** - Exclusions should only be used for generated or vendor code.

## Approval Process

1. **Minor issues (code smells)** - Developer can suppress with documented justification.
2. **Major issues (bugs, vulnerabilities)** - Requires code review approval.
3. **Critical/Blocker issues** - Requires team lead approval and must be tracked in issue tracker.

## Review and Audit

- Suppressions are reviewed during code review.
- Quarterly audit of all suppressions to ensure they are still valid.
- Suppressions older than 1 year should be re-evaluated.

## Contact

For questions about this policy or to request rule profile changes, contact the project maintainers.

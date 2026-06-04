# Reachable Go Testbed Expected Results

This file is the human-readable contract for `reach-testbed-go`. It explains
what the vulnerable baseline is expected to contain, what the remediation proof
must show, and what each synthetic issue represents.

All credentials, personal data, URLs, and suspicious strings in this repository
are synthetic. This repository is intentionally vulnerable and must not be
deployed.

## Golden Baseline

The machine-readable contract is [expected/baseline.json](expected/baseline.json).
CI validates the baseline database against that contract before remediation.

| Baseline dimension | Expected |
|--------------------|---------:|
| Raw DB signals | 28 |
| Action Required before remediation | 18 |
| Published DB demo rows | 21 |
| Attack Prompt findings | 12 |
| Attack Prompt exploitable | 9 |
| Attack Prompt defended | 3 |
| Attack Prompt errors | 0 |
| Attack Prompt skipped | 0 |

Expected signal count:

| Family | DB total | Action Required | Published DB demo rows | Expected notes |
|--------|---------:|----------------:|--------------------:|----------------|
| CVE | 1 | 1 | 1 | Reachable vulnerable Go dependency. |
| CWE | 12 | 9 | 12 | Command injection, SSRF/network fetch, and error disclosure patterns; three rows are defended by Attack Prompt and remain visible as notes. |
| Secret | 8 | 1 | 1 | One production/unknown synthetic GitHub-shaped token is actionable; workflow token names and unreachable markers are filtered. |
| DLP | 2 | 2 | 2 | Synthetic personal data logged and sent over HTTP. |
| AI | 5 | 5 | 5 | LLM calls and unguarded user-controlled flows. |

## Remediation Proof

The proof scan is a separate Reachable scan of the remediation branch. The
proof gate passes only when the database comparison shows:

| Proof target | Expected outcome |
|--------------|------------------|
| Expected vulnerable rows | Present in the baseline database. |
| Production-actionable rows after remediation | 0 |
| Post-remediation Action Required | 0 |
| Residual findings | At most filtered `NON_PROD` or `NOT_REACHABLE` fixture markers. |
| Audit and integrity checks | Passing for the proof scan. |

SARIF may be exported for platform integration, but the demo verdict is based
only on the database comparison.

## Expected Findings Table

| ID | Type | Expected risk | Expected reachability | Location | Business explanation | Expected remediation |
|----|------|---------------|-----------------------|----------|----------------------|----------------------|
| GO-CVE-01 | CVE-2022-32149 / `golang.org/x/text` | High | Reachable | `internal/handlers/cve.go`; `go.mod` | A public language parsing route exercises an old dependency with a denial-of-service advisory. | Upgrade `golang.org/x/text` to a fixed version and keep route-level input validation. |
| GO-CWE-01 | CWE / command injection | Critical | Reachable | `internal/handlers/cwe.go` | A request parameter is concatenated into a shell command. A caller could turn a diagnostic endpoint into command execution. | Remove shell string construction. Validate hostnames and pass arguments as an exec argument array or use a network library. |
| GO-CWE-02 | CWE / user-controlled URL fetch | Critical | Reachable | `internal/handlers/suspicious.go` | An admin route downloads from a caller-supplied URL. This models unsafe tool staging and SSRF-style fetch behavior. | Restrict sources to a trusted allowlist, require authentication, verify checksums/signatures, and avoid arbitrary outbound fetches. |
| GO-CWE-03 | CWE / SSRF HTTP client | Medium | Reachable | `internal/handlers/suspicious.go` | User input reaches an HTTP client, so server-side infrastructure could be asked to call untrusted destinations. | Use URL validation, deny private/internal ranges, enforce trusted schemes/hosts, and add timeouts. |
| GO-CWE-04 | CWE / error disclosure | Medium | Reachable/defended mix | `internal/handlers/cve.go` | Parser errors are returned directly to clients, potentially exposing implementation details; Attack Prompt defends the non-attacker-controlled instances. | Return generic client errors and log details internally. |
| GO-CWE-05 | CWE / error disclosure | Medium | Reachable | `internal/handlers/ai.go` | JSON decoding errors are returned directly from AI endpoints. | Return generic bad-request text and preserve details only in structured logs. |
| GO-CWE-06 | CWE / error disclosure | Medium | Reachable/defended mix | `internal/handlers/suspicious.go` | Network, file, and copy errors from the tool-fetch path are exposed to callers; Attack Prompt defends one internal-only instance. | Return generic operational errors; keep internal details in logs or audit events. |
| GO-SECRET-01 | Secret / GitHub token shape | Medium | Reachable | `internal/handlers/secrets.go` | A synthetic GitHub-shaped token is embedded in code and returned by an API. In a real system this would be a credential leak. | Rotate the value, remove it from code, load it from a secret manager, and never return it in responses. |
| GO-SECRET-02 | Secret / AWS access key shape | Info | Not reachable | `internal/handlers/secrets.go` | An AWS-shaped synthetic marker is present for detector coverage but is filtered as non-actionable in the latest proof. | Keep only synthetic test markers in fixtures; never put real cloud credentials in source. |
| GO-SECRET-03 | Secret / workflow token variables | Info | Not reachable / non-production | `.github/workflows/reachable-remediate.yml` | `GITHUB_TOKEN` and `GH_TOKEN` are environment variable names used by GitHub tooling, not real secret values. | No code fix required. They should remain filtered/non-actionable. |
| GO-DLP-01 | DLP / PII to log | Critical | Reachable | `internal/handlers/dlp.go` | Synthetic SSN and date-of-birth values are written to logs. In production this would create regulated-data exposure. | Mask sensitive values, minimize logging, and add structured audit logging without raw identifiers. |
| GO-DLP-02 | DLP / PII to outbound HTTP | Critical | Reachable | `internal/handlers/dlp.go` | Synthetic personal data is sent to an external analytics endpoint. | Remove raw PII from outbound telemetry, tokenize fields, and enforce data-sharing controls. |
| GO-AI-01 | AI / LLM API call with sensitive context | Critical | Reachable | `internal/handlers/ai.go` | User-controlled prompt content is sent to an LLM call in an admin-style context. | Separate system and user messages, treat user content as data, and apply policy checks before model calls. |
| GO-AI-02 | AI / agent tool instruction risk | Critical | Reachable | `internal/handlers/ai.go` | User input is mixed into an internal automation-agent tool specification. | Use constrained tool schemas, allowlisted actions, explicit authorization, and policy checks. |
| GO-AI-03 | AI / unguarded flow to command execution | Medium | Reachable | `internal/handlers/cwe.go` | Reachable taint flow confirms the command-injection path has user-controlled input. | Fixed by the command-injection remediation. |
| GO-AI-04 | AI / unguarded flow to error/output response | Medium | Reachable | `internal/handlers/cwe.go` | User-controlled diagnostic behavior can influence returned output. | Fixed by removing shell execution and normalizing errors. |
| GO-AI-05 | AI / unguarded flow to network fetch | Medium | Reachable | `internal/handlers/suspicious.go` | User input controls the outbound fetch destination. | Fixed by the URL allowlist and SSRF controls. |

Some rows represent multiple scanner hits on the same source file and behavior.
That is expected. The demo should show that Reachable groups the work into a
bounded remediation request rather than asking a developer to triage every raw
scanner row by hand.

## No-Fix CVE Handling

The compact Go baseline currently contains one fix-available CVE. The
remediation policy also supports no-fix CVEs: when a future scan reports a
reachable CVE without an upgrade path, the agent must implement or document a
compensating control instead of inventing a fake dependency version.

Valid compensating controls include input validation, route gating,
authentication or authorization checks, isolation, timeouts, resource limits,
and accepted-risk documentation when code change is not possible.

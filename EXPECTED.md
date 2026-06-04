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
| Raw DB signals in baseline database | 28 |
| Release blockers before remediation | 18 |
| DB evidence rows used in public proof | 21 |
| Defended attacker-evidence rows | 3 |
| Filtered fixture/nonproduction rows | 7 |
| Grouped expected findings | 17 |
| Required proof result after remediation | 0 release blockers |

Expected release decision:

| Family | Expected signals | Release blockers | Exploitability dimension | Nonblocking evidence | Expected proof |
|--------|-----------------:|-----------------:|--------------------------|---------------------|----------------|
| CVE | 1 | 1 | Reachable, not attack-proofed | 0 | Fixed dependency version; CVE row absent from proof scan. |
| CWE | 12 | 9 | 8 exploitable, 3 defended | 3 defended rows | Command execution, SSRF/network fetch, and blocking error-disclosure rows absent from proof scan. |
| Secret | 8 | 1 | Exposure | 7 filtered fixture rows | Synthetic production token absent; fixture-only markers remain non-actionable. |
| DLP | 2 | 2 | Exposure | 0 | Synthetic personal data exposure rows absent. |
| AI | 5 | 5 | 1 exploitable flow, 4 AI-boundary exposure/authority rows | 0 | AI-boundary and unguarded-flow rows absent or covered by underlying code fixes. |
| **Total** | **28** | **18** | **9 exploitable rows plus exposure/reachable blockers** | **10** | **0 release blockers after remediation.** |

## Remediation Proof

The proof scan is a separate Reachable scan of the remediation branch. The
proof gate passes only when the database comparison shows:

| Proof target | Expected outcome |
|--------------|------------------|
| Expected vulnerable rows | Present in the baseline database. |
| Release blockers after remediation | 0 |
| Post-remediation release blockers | 0 |
| Residual findings | At most filtered `NON_PROD` or `NOT_REACHABLE` fixture markers. |
| Audit and integrity checks | Passing for the proof scan. |

SARIF may be exported for platform integration, but the demo verdict is based
only on the database comparison.

## Expected Findings Table

`DB signals` shows how many raw database findings are represented by the grouped row; the column totals 28 and reconciles with the golden baseline. Exploitability is the expected attackability or exposure dimension for the grouped finding. `Exploitable` and `Defended` states require Enzo attacker evidence; `Exposure` is used for secret, PII, and sensitive-AI-boundary rows where the security impact is data exposure rather than an attacker proof.

| ID | DB signals | Type | Expected risk | Expected reachability | Expected exploitability | Location | Business explanation | Expected remediation |
|----|------------|------|---------------|-----------------------|--------------------------|----------|----------------------|----------------------|
| GO-CVE-01 | 1 | CVE-2022-32149 / `golang.org/x/text` | High | Reachable | Not attack-proofed | `internal/handlers/cve.go`; `go.mod` | A public language parsing route exercises an old dependency with a denial-of-service advisory. | Upgrade `golang.org/x/text` to a fixed version and keep route-level input validation. |
| GO-CWE-01 | 1 | CWE / command injection | Critical | Reachable | Exploitable | `internal/handlers/cwe.go` | A request parameter is concatenated into a shell command. A caller could turn a diagnostic endpoint into command execution. | Remove shell string construction. Validate hostnames and pass arguments as an exec argument array or use a network library. |
| GO-CWE-02 | 1 | CWE / user-controlled URL fetch | Critical | Reachable | Exploitable | `internal/handlers/suspicious.go` | An admin route downloads from a caller-supplied URL. This models unsafe tool staging and SSRF-style fetch behavior. | Restrict sources to a trusted allowlist, require authentication, verify checksums/signatures, and avoid arbitrary outbound fetches. |
| GO-CWE-03 | 1 | CWE / SSRF HTTP client | Medium | Reachable | Exploitable | `internal/handlers/suspicious.go` | User input reaches an HTTP client, so server-side infrastructure could be asked to call untrusted destinations. | Use URL validation, deny private/internal ranges, enforce trusted schemes/hosts, and add timeouts. |
| GO-CWE-04 | 3 | CWE / error disclosure | Medium | Mixed blocking/nonblocking | Mixed exploitable/defended | `internal/handlers/cve.go` | Parser errors are returned directly to clients, potentially exposing implementation details; non-attacker-controlled instances are retained as nonblocking evidence. | Return generic client errors and log details internally. |
| GO-CWE-05 | 3 | CWE / error disclosure | Medium | Reachable | Exploitable | `internal/handlers/ai.go` | JSON decoding errors are returned directly from AI endpoints. | Return generic bad-request text and preserve details only in structured logs. |
| GO-CWE-06 | 3 | CWE / error disclosure | Medium | Mixed blocking/nonblocking | Mixed exploitable/defended | `internal/handlers/suspicious.go` | Network, file, and copy errors from the tool-fetch path are exposed to callers; one internal-only instance is retained as nonblocking evidence. | Return generic operational errors; keep internal details in logs or audit events. |
| GO-SECRET-01 | 1 | Secret / GitHub token shape | Medium | Reachable | Exposure | `internal/handlers/secrets.go` | A synthetic GitHub-shaped token is embedded in code and returned by an API. In a real system this would be a credential leak. | Rotate the value, remove it from code, load it from a secret manager, and never return it in responses. |
| GO-SECRET-02 | 1 | Secret / AWS access key shape | Info | Not reachable | Not applicable | `internal/handlers/secrets.go` | An AWS-shaped synthetic marker is present for detector coverage but is filtered as non-actionable in the latest proof. | Keep only synthetic test markers in fixtures; never put real cloud credentials in source. |
| GO-SECRET-03 | 6 | Secret / workflow token variables | Info | Not reachable / non-production | Not applicable | `.github/workflows/reachable-remediate.yml` | `GITHUB_TOKEN` and `GH_TOKEN` are environment variable names used by GitHub tooling, not real secret values. | No code fix required. They should remain filtered/non-actionable. |
| GO-DLP-01 | 1 | DLP / PII to log | Critical | Reachable | Exposure | `internal/handlers/dlp.go` | Synthetic SSN and date-of-birth values are written to logs. In production this would create regulated-data exposure. | Mask sensitive values, minimize logging, and add structured audit logging without raw identifiers. |
| GO-DLP-02 | 1 | DLP / PII to outbound HTTP | Critical | Reachable | Exposure | `internal/handlers/dlp.go` | Synthetic personal data is sent to an external analytics endpoint. | Remove raw PII from outbound telemetry, tokenize fields, and enforce data-sharing controls. |
| GO-AI-01 | 1 | AI / LLM API call with sensitive context | Critical | Reachable | Exposure | `internal/handlers/ai.go` | User-controlled prompt content is sent to an LLM call in an admin-style context. | Separate system and user messages, treat user content as data, and apply policy checks before model calls. |
| GO-AI-02 | 1 | AI / agent tool instruction risk | Critical | Reachable | Reachable authority risk | `internal/handlers/ai.go` | User input is mixed into an internal automation-agent tool specification. | Use constrained tool schemas, allowlisted actions, explicit authorization, and policy checks. |
| GO-AI-03 | 1 | AI / unguarded flow to command execution | Medium | Reachable | Exploitable | `internal/handlers/cwe.go` | Reachable taint flow confirms the command-injection path has user-controlled input. | Fixed by the command-injection remediation. |
| GO-AI-04 | 1 | AI / unguarded flow to error/output response | Medium | Reachable | Exploitable | `internal/handlers/cwe.go` | User-controlled diagnostic behavior can influence returned output. | Fixed by removing shell execution and normalizing errors. |
| GO-AI-05 | 1 | AI / unguarded flow to network fetch | Medium | Reachable | Exploitable | `internal/handlers/suspicious.go` | User input controls the outbound fetch destination. | Fixed by the URL allowlist and SSRF controls. |
| **Total** | **28** |  |  |  |  |  |  |  |

## No-Fix CVE Handling

The compact Go baseline currently contains one fix-available CVE. The
remediation policy also supports no-fix CVEs: when a future scan reports a
reachable CVE without an upgrade path, the agent must implement or document a
compensating control instead of inventing a fake dependency version.

Valid compensating controls include input validation, route gating,
authentication or authorization checks, isolation, timeouts, resource limits,
and accepted-risk documentation when code change is not possible.

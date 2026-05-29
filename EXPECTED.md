# Reachable Go Testbed Expected Results

This file is the customer-facing baseline for `reach-testbed-go`. It explains
what the demo is expected to find before remediation, what a clean proof looks
like after remediation, and what each issue means in plain language.

All credentials, personal data, URLs, and suspicious strings in this repository
are synthetic. This repository is intentionally vulnerable and must not be
deployed.

## Golden Baseline

Latest verified baseline:

```text
repo:    /Users/alaindazzi/src/reach-testbed-go
branch:  main
scan:    /Users/alaindazzi/.reachable/scans/reach-testbed-go-64462931/main/20260529-081617-9b16e1
result:  25 signals, 22 actionable
```

Expected signal count:

| Family | Expected total | Expected actionable | Expected notes |
|--------|----------------|--------------------|----------------|
| CVE | 1 | 1 | Reachable vulnerable Go dependency. |
| CWE | 12 | 12 | Command injection, SSRF/network fetch, and error disclosure patterns. |
| Secret | 5 | 2 | Two reachable synthetic tokens plus three intentionally filtered/non-actionable markers. |
| DLP | 2 | 2 | Synthetic personal data logged and sent over HTTP. |
| AI | 5 | 5 | LLM calls and unguarded user-controlled flows. |

Expected remediation proof:

| Proof target | Expected outcome |
|--------------|------------------|
| `go test ./...` | Passes before and after remediation. |
| Post-remediation scan | `ACTION REQUIRED 0`. |
| Residual findings | At most filtered `NOT_REACHABLE` synthetic secret markers. |
| `reachctl audit --latest --summary` | Passes data-quality checks. |
| `reachctl integrity --latest` | Passes dashboard/database integrity checks. |

## Expected Findings Table

| ID | Type | Expected risk | Expected reachability | Location | Business explanation | Expected remediation |
|----|------|---------------|-----------------------|----------|----------------------|----------------------|
| GO-CVE-01 | CVE-2022-32149 / `golang.org/x/text` | High | Reachable | `internal/handlers/cve.go`; `go.mod` | A public language parsing route exercises an old dependency with a denial-of-service advisory. | Upgrade `golang.org/x/text` to a fixed version and keep route-level input validation. |
| GO-CWE-01 | CWE / command injection | Critical | Reachable | `internal/handlers/cwe.go` | A request parameter is concatenated into a shell command. A caller could turn a diagnostic endpoint into command execution. | Remove shell string construction. Validate hostnames and pass arguments as an exec argument array or use a network library. |
| GO-CWE-02 | CWE / user-controlled URL fetch | Critical | Reachable | `internal/handlers/suspicious.go` | An admin route downloads from a caller-supplied URL. This models unsafe tool staging and SSRF-style fetch behavior. | Restrict sources to a trusted allowlist, require authentication, verify checksums/signatures, and avoid arbitrary outbound fetches. |
| GO-CWE-03 | CWE / SSRF HTTP client | Medium | Reachable | `internal/handlers/suspicious.go` | User input reaches `http.Get`, so server-side infrastructure could be asked to call untrusted destinations. | Use URL validation, deny private/internal ranges, enforce trusted schemes/hosts, and add timeouts. |
| GO-CWE-04 | CWE / error disclosure | Medium | Reachable | `internal/handlers/cve.go` | Parser errors are returned directly to clients, potentially exposing implementation details. | Return generic client errors and log details internally. |
| GO-CWE-05 | CWE / error disclosure | Medium | Reachable | `internal/handlers/ai.go` | JSON decoding errors are returned directly from AI endpoints. | Return generic bad-request text and preserve details only in structured logs. |
| GO-CWE-06 | CWE / error disclosure | Medium | Reachable | `internal/handlers/suspicious.go` | Network, file, and copy errors from the tool-fetch path are exposed to callers. | Return generic operational errors; keep internal details in logs or audit events. |
| GO-SECRET-01 | Secret / GitHub token shape | Medium | Reachable | `internal/handlers/secrets.go` | A synthetic GitHub-shaped token is embedded in code and returned by an API. In a real system this would be a credential leak. | Rotate the value, remove it from code, load it from a secret manager, and never return it in responses. |
| GO-SECRET-02 | Secret / duplicate detector confirmation | Medium | Reachable | `internal/handlers/secrets.go` | A second scanner independently confirms the same reachable synthetic token. | Same as `GO-SECRET-01`; duplicate detections should collapse into the same remediation work. |
| GO-SECRET-03 | Secret / AWS access key shape | Info | Not reachable | `internal/handlers/secrets.go` | An AWS-shaped synthetic marker is present for detector coverage but is filtered as non-actionable in the latest proof. | Keep only synthetic test markers in fixtures; never put real cloud credentials in source. |
| GO-SECRET-04 | Secret / workflow token variables | Info | Not reachable | `.github/workflows/reachable-remediate.yml` | `GITHUB_TOKEN` and `GH_TOKEN` are environment variable names used by GitHub tooling, not real secret values. | No code fix required. They should remain filtered/non-actionable. |
| GO-DLP-01 | DLP / PII to log | Critical | Reachable | `internal/handlers/dlp.go` | Synthetic SSN and date-of-birth values are written to logs. In production this would create regulated-data exposure. | Mask sensitive values, minimize logging, and add structured audit logging without raw identifiers. |
| GO-DLP-02 | DLP / PII to outbound HTTP | Critical | Reachable | `internal/handlers/dlp.go` | Synthetic personal data is sent to an external analytics endpoint. | Remove raw PII from outbound telemetry, tokenize fields, and enforce data-sharing controls. |
| GO-AI-01 | AI / LLM API call with sensitive context | Critical | Reachable | `internal/handlers/ai.go` | User-controlled prompt content is sent to an LLM call in an admin-style context. | Separate system and user messages, treat user content as data, and apply policy checks before model calls. |
| GO-AI-02 | AI / agent tool instruction risk | Critical | Reachable | `internal/handlers/ai.go` | User input is mixed into an internal automation-agent tool specification. | Use constrained tool schemas, allowlisted actions, explicit authorization, and policy checks. |
| GO-AI-03 | AI / unguarded flow to command execution | Medium | Reachable | `internal/handlers/cwe.go` | Reachable taint flow confirms the command-injection path has user-controlled input. | Fixed by the command-injection remediation. |
| GO-AI-04 | AI / unguarded flow to error/output response | Medium | Reachable | `internal/handlers/cwe.go` | User-controlled diagnostic behavior can influence returned output. | Fixed by removing shell execution and normalizing errors. |
| GO-AI-05 | AI / unguarded flow to network fetch | Medium | Reachable | `internal/handlers/suspicious.go` | User input controls the outbound fetch destination. | Fixed by the URL allowlist and SSRF controls. |

Some rows represent multiple scanner hits on the same source file and behavior.
That is expected. The demo should show that Reachable groups the work into a
bounded remediation prompt rather than asking a developer to manually triage
every raw scanner row.

## No-Fix CVE Handling

The compact Go baseline currently contains one fix-available CVE. The prompt
contract also supports no-fix CVEs: when a future scan reports a reachable CVE
without an upgrade path, the agent must implement or document compensating
controls instead of inventing a fake dependency version.

Valid compensating controls include:

- input validation and size limits
- feature disablement or route gating
- authentication/authorization checks
- isolation, timeout, and resource limits
- explicit accepted-risk documentation when code change is not possible

## Commands

Baseline validation:

```bash
cd /Users/alaindazzi/src/reach-core
scripts/reach-testbed-go-agent-loop.sh \
  --fixture /Users/alaindazzi/src/reach-testbed-go \
  --base-branch main \
  --branch reachable-remediate-demo-$(date +%Y%m%d%H%M%S)
```

Full local remediation proof with Codex:

```bash
cd /Users/alaindazzi/src/reach-core
scripts/reach-testbed-go-agent-loop.sh \
  --fixture /Users/alaindazzi/src/reach-testbed-go \
  --base-branch main \
  --branch reachable-remediate-codex-$(date +%Y%m%d%H%M%S) \
  --agent codex \
  --run-agent \
  --prove
```

Full local remediation proof with OpenCode:

```bash
cd /Users/alaindazzi/src/reach-core
OPENCODE_MODEL=opencode/deepseek-v4-flash-free \
scripts/reach-testbed-go-agent-loop.sh \
  --fixture /Users/alaindazzi/src/reach-testbed-go \
  --base-branch main \
  --branch reachable-remediate-opencode-$(date +%Y%m%d%H%M%S) \
  --agent opencode \
  --run-agent \
  --prove
```

Claude Code uses the same harness with `--agent claude`; for CI demos the
matching one-key mode is `remediation_mode=claude-anthropic` with a single
`ANTHROPIC_API_KEY` GitHub secret. The Codex CI demo mode is
`remediation_mode=codex-openai` with a single `OPENAI_API_KEY` GitHub secret.

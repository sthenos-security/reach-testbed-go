# reach-testbed-go

Intentionally vulnerable Go fixture repository for demonstrating Reachable
CI/CD scanning and automated remediation with coding agents.

> Do not deploy this application. It contains synthetic security issues for
> scanner validation only.

![Reachable CI autoremediation flow](docs/remediation-flow.svg)

## What This Demo Proves

This repository is the compact Go demo for the Reachable remediation workflow:

1. Reachable scans the repository and records database-backed signal truth.
2. Reachable generates a bounded remediation prompt bundle.
3. A selected coding agent applies one or more serialized fix batches.
4. CI rescans the branch, audits, and verifies integrity.
5. CI opens one reviewable `reachable-remediate-*` branch and pull request.

The process is intentionally branch-first. The safe default is scan-only:
`remediate=false` means CI will not edit code.

## Public Demo Pages

The latest public scan/remediation summary is published to GitHub Pages:

<https://sthenos-security.github.io/reach-testbed-go/>

This is the customer-friendly view for demos. It lists the last selected SARIF
report, top exploitable/reachable issues, reachability counts, remediation
ledger status, and links back to the Actions run and GitHub code scanning. It is
a sanitized mini-dashboard, not the full local Reachable dashboard: raw prompt
bundles, agent transcripts, local databases, private logs, and generated rule
internals are not published.

## Expected Results

The customer-facing baseline manifest lives in [EXPECTED.md](EXPECTED.md). The
static demo page lives in [docs/expected-results.html](docs/expected-results.html).

Current golden baseline:

| Result | Expected |
|--------|----------|
| Raw signals | 25 |
| Actionable before remediation | 22 |
| Families | CVE, CWE, secret, DLP, AI |
| Actionable after remediation | 0 |
| Residual post-fix findings | Filtered `NOT_REACHABLE` synthetic secret markers only |

## Layout

```text
cmd/server/              HTTP entrypoint and route registration
internal/handlers/       Reachable, defended, and assess signal cases
internal/safety/         Guard helpers used by defended cases
config/                  Synthetic insecure configuration cases
deploy/                  Synthetic IaC cases
testdata/dlp/            Synthetic DLP corpus
docs/remediation-flow.svg High-level customer-safe process diagram
EXPECTED.md              Customer-facing baseline manifest
.github/workflows/       Drop-in remediation workflow template
ci/run-agent.sh          Agent executor shim used by CI and local runs
```

## Optional Local App Smoke Test

```bash
go test ./...
go run ./cmd/server
```

The service listens on `:8080` by default. The remediation CI demo does not
run application tests; its proof is the final Reachable scan, audit, integrity
check, SARIF upload, and remediation ledger.

## Local Remediation Harness

Agentic remediation is not a `reachctl scan` flag. The scan remains the
source-of-truth proof step. Batch remediation is:

```text
reachctl scan -> reachctl remediate -> coding agent -> reachctl scan -> audit/integrity
```

`reachctl vibe remediate` is the continuous local vibe-coding daemon loop. The
workflow in this repository is different: it is a one-branch CI/manual
remediation loop that generates a prompt bundle and invokes the selected agent
explicitly.

Run a scan-only baseline and prompt-bundle check:

```bash
cd /Users/alaindazzi/src/reach-core
scripts/reach-testbed-go-agent-loop.sh \
  --fixture /Users/alaindazzi/src/reach-testbed-go \
  --base-branch main \
  --branch reachable-remediate-demo-$(date +%Y%m%d%H%M%S)
```

Run Codex end to end locally. Local Codex usually uses the login and model
already configured by the Codex CLI; Reachable scan credentials still come from
`reachctl doctor` / the Reachable credential store unless you override them:

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

Run OpenCode end to end locally:

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

Run Claude Code end to end locally:

```bash
cd /Users/alaindazzi/src/reach-core
ANTHROPIC_API_KEY=... \
scripts/reach-testbed-go-agent-loop.sh \
  --fixture /Users/alaindazzi/src/reach-testbed-go \
  --base-branch main \
  --branch reachable-remediate-claude-$(date +%Y%m%d%H%M%S) \
  --agent claude \
  --run-agent \
  --prove
```

## CI/CD Remediation Template

The workflow at [.github/workflows/reachable-remediate.yml](.github/workflows/reachable-remediate.yml)
is written as a reusable template. It is Go-ready by default, but the same shape
works for other languages by changing `scan_extra_flags` and the selected
coding agent.

Important manual inputs:

| Input | Purpose |
|-------|---------|
| `remediate` | Main kill switch. `false` means scan-only proof and no code changes. |
| `rescan_only` | Proves an existing branch without creating or editing a branch. |
| `target_branch` | Base branch, or existing remediation branch when `rescan_only=true`. |
| `remediation_mode` | One-key mode: `codex-openai`, `claude-anthropic`, `opencode`, or `custom`. |
| `opencode_model` | OpenCode model slug when `remediation_mode=opencode`. |
| `prompt_profile` | Remediation profile: `safe`, `balanced`, `aggressive`, `release`, or `nightly`. |
| `signal_types` | `all`, or a comma-separated subset such as `cve,cwe,secret`. |
| `max_batches` | Maximum serialized remediation batches. Use this to avoid huge prompts. |
| `rescan_strategy` | `final` runs one Reachable proof scan after all batches; `each_batch` rescans after every batch. |
| `scan_extra_flags` | Extra `reachctl scan` flags. |
| `custom_agent_*` | Install/run commands for an agent wrapper not built into the template. |
| `create_pr` | Open a PR after successful remediation. |

For the investor/customer CI demo, use one mode and one matching provider key:

| Mode | Required GitHub secret | What it drives |
|------|------------------------|----------------|
| `codex-openai` | `OPENAI_API_KEY` | Reachable OpenAI scan/enrichment plus Codex remediation. |
| `claude-anthropic` | `ANTHROPIC_API_KEY` | Reachable Claude scan/enrichment plus Claude Code remediation. |

OpenCode and custom modes remain available for advanced runners, but they are
not the simplest demo path.

Additional supported GitHub secrets and variables:

| Name | Used by |
|------|---------|
| `REACHABLE_API_KEY` | Optional Reachable cloud publish/org attach. |
| `REACHABLE_GITHUB_TOKEN` | Optional fine-grained token for opening PRs when repository Actions settings block PR creation by `GITHUB_TOKEN`. Needs Contents and Pull requests write permissions. |
| `MCP_GITHUB_TOKEN` | MCP-based agent GitHub access. |
| `OPENROUTER_API_KEY` | Optional Reachable OpenRouter provider for non-demo scan/enrichment. |
| `ANTHROPIC_API_KEY` | One-key `claude-anthropic` mode. |
| `OPENAI_API_KEY` | One-key `codex-openai` mode. |
| `GROQ_API_KEY` | Reachable Groq provider. |
| `GROK_API_KEY` | Legacy typo alias; the workflow maps it to `GROQ_API_KEY` if needed. |
| `DEEPSEEK_API_KEY` | Direct DeepSeek-compatible agent/provider setups. |
| `MOONSHOT_API_KEY` | Direct Moonshot-compatible agent/provider setups. |
| `XAI_API_KEY` | xAI/Grok-compatible provider setups. |
| `CODEX_API_KEY` | Compatibility alias; the workflow maps it to `OPENAI_API_KEY` when `OPENAI_API_KEY` is absent. |
| `CLAUDE_CODE_OAUTH_TOKEN` | Claude Code OAuth-based CI auth. |
| `OPENCODE_AUTH` | OpenCode auth if the selected model requires it. |
| `REACHABLE_PRIVATE_LLM_MODEL` | Optional repository/org variable for enterprise runners. |
| `REACHABLE_PRIVATE_LLM_API_KEY` | Optional private/local model key. |
| `ENZO_LOCAL_MODEL` | Optional local Enzo/private model variable. |
| `ENZO_LOCAL_API_KEY` | Optional local Enzo/private model key. |
| `REACHABLE_DIST_REPO` | Optional repository/org variable that points at the install distribution repo. Defaults to `sthenos-security/reach-dist`. |
| `REACHABLE_VERSION` | Optional version pin for demos or customer rollouts. Defaults to latest. |

`GITHUB_TOKEN` is provided by GitHub Actions. The workflow grants it write
access to contents, pull requests, and security events so it can push the
remediation branch, open a PR, and upload SARIF. Some repositories disable the
GitHub Actions setting that lets the built-in token create pull requests. In
that case the workflow still pushes the `reachable-remediate-*` branch and logs
the branch URL; set `REACHABLE_GITHUB_TOKEN` or enable that repository setting
when you want PR creation to be fully automatic.

### CI Cache

The workflow restores and saves Reachable state with `actions/cache@v4`:

```text
~/.reachable
```

The Actions log prints `Reachable cache active` before the baseline scan. A
warm run says `warm cache restored`; the first run says `cold start` and then
populates the cache for the next run. This keeps repeat CI scans fast by
preserving scanner databases, package/source caches, repo scan state, and
Reachable tool downloads. The same setup block logs repository size and then
runs `reachctl loc .` after installation so demo operators can quote the
same LOC telemetry that Reachable uses internally.

### Published CI Reports

Every scan writes an actionable-production SARIF issue report into
`.reachable/ci-artifacts/`:

| File | Purpose |
|------|---------|
| `reachable.sarif` | Baseline issue report for GitHub code scanning. |
| `reachable-after-batch-<n>.sarif` | Post-remediation issue report after batch `<n>`. |

The SARIF report contains production findings that are `reachable` or
`unknown` and not defended by the attack pass. `NON_PROD`, `NOT_REACHABLE`,
and defended/noise findings stay out of CI code-scanning results. The workflow
uploads these SARIF files as artifacts and can post them to GitHub code
scanning when the repository enables SARIF upload. The workflow also publishes a
small GitHub Pages mini-dashboard for the latest run at
<https://sthenos-security.github.io/reach-testbed-go/>. In CI mode we do not
publish the full local Reachable dashboard by default; customers already have
their build loop, and SARIF plus the sanitized Pages summary are the right
public issue transport for CI.

The workflow selects the strongest available SARIF for GitHub Code Scanning:
final proof scan first, latest batch proof scan next, then baseline scan. The
Actions job summary prints the selected SARIF path, actionable result count,
SARIF levels, upload outcome, and a direct link to
`Security > Code scanning` filtered to `category:reachable`. The Pages summary
prioritizes the top exploitable/reachable issues first, then falls back to
unknown actionable findings when no reachable issue remains. If GitHub rejects
SARIF upload because code scanning is disabled for the repository, the same
SARIF, Pages files, and proof artifacts remain attached to the workflow run.

Each scan also publishes compact support/proof logs under
`.reachable/ci-artifacts/reports/<label>/`:

| File | Purpose |
|------|---------|
| `scan.log` | Full scan log. |
| `audit.txt` | Data-quality and issue audit output. |
| `integrity.txt` | SARIF/database integrity proof. |
| `compliance.md` / `compliance.json` | DB-backed compliance evidence pack when supported by the installed Reachable wheel. |
| `scan-path.txt` | Original runner scan session path. |

The baseline scan is labeled `baseline`, rescan-only proof is labeled
`rescan-only`, post-remediation proof scans are labeled `after-final` by
default, and `after-batch-<n>` when `rescan_strategy=each_batch`.

The workflow also writes a remediation ledger:

| File | Purpose |
|------|---------|
| `.reachable/ci-artifacts/remediation-ledger.json` | Machine-readable before/attempt/after ledger. |
| `.reachable/ci-artifacts/remediation-ledger.md` | Human-readable summary for PRs and support. |

The ledger records what SARIF found, which Reachable rules were sent to the
agent, which agent log corresponds to the attempt, and whether the final proof
SARIF is clean. If findings remain, the status is
`needs_retry_or_human_review`; the next CI batch must be generated from the
updated branch/database state.

The happy path should not retry. The agent should fix the selected batch and
the final proof scan should be clean. Use multiple batches only when the
remediation queue is too large or logically unrelated for one prompt. The
default `rescan_strategy=final` is faster: scan, remediate batch or batches,
then run one Reachable proof rescan at the end. Use `rescan_strategy=each_batch`
when debugging or when a regulated workflow needs per-batch proof artifacts.

Reachable does not own the customer's build/test loop. Customers can run this
remediation job before, after, or inside their existing CI pipeline, but this
template only scans, remediates, rescans, and publishes proof.

## Agent Strategy

Reachable owns scanning, ranking, prompt-bundle generation, audit artifacts, and
post-fix proof. The selected coding agent only consumes `prompt.md` and edits
the current branch.

The public demo workflow treats all runner output and uploaded artifacts as
public. It does not upload raw remediation bundles, full rule packs, skills
databases, fuzz/pentest prompts, or agent transcripts. Reachable stores the
durable audit in `repo.db` as sanitized metadata: prompt and bundle hashes,
selected rule IDs, workflow inputs, before/after SARIF summaries, public
artifact fingerprints, and outcome status. The exported ledger files are
rendered summaries for PRs and support, not the source of truth.

Generated `.reachable/remediation-bundle/` files are intentionally ignored by
git and should be treated as ephemeral runner-local inputs. The CI shim feeds
prompts to supported agents through stdin or file attachment instead of putting
the full prompt in the process argument list. Agent logs are retained only in a
private runner-local directory by default; public artifacts contain SARIF,
audit, integrity, compliance, and sanitized remediation ledger reports.

Supported CI executor modes:

| Agent | Install path in template | Notes |
|-------|--------------------------|-------|
| Claude Code | `npm install -g @anthropic-ai/claude-code` | Best default for GitHub-hosted CI when auth is configured. |
| Codex | `npm install -g @openai/codex` | Uses `codex exec` in non-interactive mode. |
| OpenCode | `npm install -g opencode-ai` | Use `opencode_model` to choose the model. |
| Custom | User-supplied install/run command | For wrappers, GitHub Actions, or future agents. |

Cursor is supported as a local MCP target, but it is not a GitHub-hosted CI
executor in this template.

## No-Fix CVEs

When Reachable reports a reachable CVE with no fixed version, the generated
prompt tells the agent not to invent a dependency upgrade. The agent must add a
compensating control when possible, such as validation, gating, isolation,
timeouts, or explicit accepted-risk documentation.

## CI Dry Run

Before enabling remediation:

1. Add the secrets above.
2. Run the workflow with `remediate=false`.
3. Confirm baseline SARIF and audit artifacts upload.
4. Run with `remediate=true`, `remediation_mode=codex-openai` or
   `remediation_mode=claude-anthropic`, and
   `max_batches=1`.
5. Review the generated `reachable-remediate-*` pull request.

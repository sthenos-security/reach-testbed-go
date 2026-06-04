# reach-testbed-go

Intentionally vulnerable Go fixture repository for demonstrating Reachable
CI/CD scanning, agentic remediation, and DB-backed post-fix proof.

> Do not deploy this application. It contains synthetic security issues for
> scanner validation and controlled demos only.

![Reachable CI remediation flow](docs/remediation-flow.svg)

## Start Here

| Question | Answer |
|----------|--------|
| What is this repo? | A controlled vulnerable Go application used to demonstrate Reachable CI scanning, autonomous remediation, and DB-backed proof that a remediation branch is clean. |
| What do I configure? | Add one AI key as a repository secret: `OPENAI_API_KEY` for `codex-openai` / Codex (OpenAI), or `ANTHROPIC_API_KEY` for `claude-anthropic` / Claude Code (Anthropic). Optional workflow inputs are listed below. |
| Where is the CI pipeline? | [.github/workflows/reachable-remediate.yml](.github/workflows/reachable-remediate.yml). That workflow scans, optionally remediates, rescans, verifies the DB proof, and publishes sanitized evidence. |
| Where do I run it? | GitHub Actions → [Reachable Remediation Template](https://github.com/sthenos-security/reach-testbed-go/actions/workflows/reachable-remediate.yml). |
| Where are the verdict and artifacts? | [Public proof page](https://sthenos-security.github.io/reach-testbed-go/) and [published artifacts](https://sthenos-security.github.io/reach-testbed-go/#artifacts). |
| What is the expected vulnerable contract? | [EXPECTED.md](EXPECTED.md) and [expected/baseline.json](expected/baseline.json). |

## Demo Verdict

The public demo page is the release-facing proof view for the last published
successful proof:

<https://sthenos-security.github.io/reach-testbed-go/>

That page is built from Reachable scan evidence. It shows the branch, commit,
scan ID, and CI run it came from. The GitHub Actions workflow list remains the
authority for the latest run status. It shows:

| Evidence | What the viewer should understand |
|----------|-------------------------------------|
| Vulnerable baseline | The known vulnerable `main` branch was scanned and matched the expected issue contract. |
| Remediation branch | CI created a reviewable remediation branch and applied the agent fixes there. |
| Proof scan | Reachable rescanned the remediated branch and compared the result to the expected contract. |
| Final verdict | The demo passes only when the proof database has zero release blockers. |
| Audit metadata | Branch, commit, scan number, timestamp, runtime, AI token count, and estimated AI cost are displayed for traceability. |
| Sanitized artifacts | Convenience exports are linked for review; private prompts, rules, agent transcripts, raw witnesses, and local databases are not published. |

The scan database is the source of truth for the demo verdict. SARIF may be
generated for platform compatibility, but it is only an export report. It is
not the authority for the pass/fail claim.

## CI Validation Flow

The workflow in [.github/workflows/reachable-remediate.yml](.github/workflows/reachable-remediate.yml)
is the implementation. At a high level, each demo run follows this sequence:

1. CI checks out the vulnerable baseline branch.
2. Reachable installs or updates, records cache evidence, and scans the
   baseline into `repo.db`.
3. The baseline database is compared with [expected/baseline.json](expected/baseline.json).
   A mismatch fails the run because the testbed contract is no longer intact.
4. Reachable synthesizes a bounded remediation request from the database.
5. The selected coding agent edits a dedicated `reachable-remediate-*` branch.
6. The project test command runs to catch ordinary build or behavior breaks.
7. Reachable rescans the remediation branch into a new proof database.
8. The proof database is compared with the expected contract. The pass
   condition is zero remaining release blockers. Rescan-only verification uses
   the same database release-blocker gate; SARIF is never the pass/fail source.
9. CI publishes a sanitized Pages report and support artifacts with the exact
   scan IDs, branch names, commits, timestamps, runtime, cache state, and AI
   cost telemetry.

This is branch-first by design. The tool fixes code on a remediation branch so
a release manager can inspect the diff, verify the proof, and merge only after
normal review.

## Expected Findings

The expected vulnerable contract is documented in [EXPECTED.md](EXPECTED.md)
and enforced by [expected/baseline.json](expected/baseline.json).

Current golden baseline:

| Result | Expected |
|--------|----------|
| Raw DB signals | 28 |
| Release blockers before remediation | 18 |
| DB evidence rows used in public proof | 21 |
| Families | CVE, CWE, secret, DLP, AI |
| Grouped expected findings | 17 grouped findings covering 28 raw DB signals. |
| Release blockers after remediation | 0 |
| Residual post-fix findings | Only filtered `NON_PROD` or `NOT_REACHABLE` fixture markers may remain in the database. |

The testbed itself is the contract. Do not edit the vulnerable fixture or the
expected manifest just to make a scan pass; scanner logic must conform to the
golden behavior.

## Published Artifacts

The Pages report links a small set of public artifacts. These are review aids,
not private execution material.

| Artifact | Purpose |
|----------|---------|
| [summary.json](https://sthenos-security.github.io/reach-testbed-go/summary.json) | Compact DB-backed run summary for the public page. |
| [db-remediation-verdict.json](https://sthenos-security.github.io/reach-testbed-go/db-remediation-verdict.json) | Machine-readable baseline/proof comparison and final verdict. |
| [reachable.sarif](https://sthenos-security.github.io/reach-testbed-go/reachable.sarif) | Compatibility export for GitHub Code Scanning; not the demo verdict source. |
| [remediation-ledger.json](https://sthenos-security.github.io/reach-testbed-go/remediation-ledger.json) | Sanitized remediation summary with rule IDs and outcomes, not prompt text. |
| [compliance.json](https://sthenos-security.github.io/reach-testbed-go/compliance.json) | DB-backed compliance evidence extract. |
| [compliance-narrative.json](https://sthenos-security.github.io/reach-testbed-go/compliance-narrative.json) | Evidence-cited narrative draft for review, not a legal attestation. |
| [expected-results.html](https://sthenos-security.github.io/reach-testbed-go/expected-results.html) | Branded expected issue contract and baseline proof criteria. |

The workflow must not publish raw remediation bundles, prompt text, generated
rule packs, skills databases, fuzz or pentest prompts, agent transcripts, raw
witness payloads, or local `repo.db` files.

## Agent Lanes And Workflow Inputs

The demo supports two simple CI lanes:

| Lane | Secret | Agent |
|------|--------|-------|
| `codex-openai` | `OPENAI_API_KEY` | Codex (OpenAI) |
| `claude-anthropic` | `ANTHROPIC_API_KEY` | Claude Code (Anthropic) |

The workflow inputs are the operational guardrails. They define whether the
run only scans, creates a remediation branch, verifies an existing branch, or
publishes fresh evidence.

| Input | Default | Purpose |
|-------|---------|---------|
| `remediate` | `false` | Main kill switch. When false, CI scans and publishes evidence without changing code. |
| `rescan_only` | `false` | Verifies `target_branch` as an existing branch; does not invoke an agent or create edits. |
| `target_branch` | `main` | Baseline branch for normal runs, or the branch to verify when `rescan_only=true`. |
| `remediation_mode` | `codex-openai` | Selects the agent lane and matching provider secret. |
| `prompt_profile` | `balanced` | Controls how aggressively Reachable bundles remediation work. |
| `signal_types` | `all` | Limits remediation to selected signal families, or leaves all families eligible. |
| `max_batches` | `1` | Bounds the number of serialized agent remediation batches. |
| `rescan_strategy` | `final` | Runs proof scans only at the end or after each batch. |
| `scan_extra_flags` | empty | Optional extra scan flags for advanced test runs. |
| `require_ai` | `true` | Fails early unless the selected provider key is configured. |
| `fresh_scan` | `false` | Starts from an empty `~/.reachable` cache for a clean evidence run. |
| `create_pr` | `true` | Opens a remediation pull request when code changes are successfully produced. |
| `run_project_tests` | `true` | Runs the repository safety gate before proof scans. |
| `project_test_command` | `go test ./...` | Command used for the post-agent safety gate. |

The public report should make the selected branch, commit, scan number, final
proof state, cache state, and artifact links obvious without requiring the
viewer to know these inputs.

## Repository Layout

```text
cmd/server/                HTTP entrypoint and route registration
internal/handlers/         Vulnerable, defended, and assess signal cases
internal/safety/           Guard helpers used by defended cases
config/                    Synthetic insecure configuration cases
deploy/                    Synthetic IaC cases
testdata/dlp/              Synthetic DLP corpus
expected/baseline.json     Machine-readable expected scanner contract
ci/                        DB proof, page summary, and CI helper scripts
docs/                      Public demo page assets and sanitized reports
.github/workflows/         CI remediation and cleanup workflows
```

## What “Fixed” Means

For this demo, “fixed” means:

1. The vulnerable baseline database contained the expected issue.
2. The remediation branch proof database no longer contains that production
   actionable issue.
3. The proof gate reports zero remaining release blockers.
4. The public report displays the branch, commit, scan ID, timestamp, and
   artifact links that produced the verdict.

That is the story the demo page must tell. Anything else is support detail.

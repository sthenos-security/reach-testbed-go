#!/usr/bin/env python3
"""Write a compact before/attempt/after remediation ledger for CI artifacts."""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - CI support script
        return {"_error": f"failed to parse {path}: {exc}"}


def _sarif_results(path: Path) -> list[dict[str, Any]]:
    data = _load_json(path)
    results: list[dict[str, Any]] = []
    for run in data.get("runs") or []:
        for result in run.get("results") or []:
            if isinstance(result, dict):
                results.append(result)
    return results


def _sarif_summary(path: Path) -> dict[str, Any]:
    results = _sarif_results(path)
    by_level: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    for result in results:
        level = str(result.get("level") or "warning")
        rule_id = str(result.get("ruleId") or "unknown")
        by_level[level] = by_level.get(level, 0) + 1
        by_rule[rule_id] = by_rule.get(rule_id, 0) + 1
    return {
        "path": str(path),
        "exists": path.exists(),
        "results": len(results),
        "by_level": dict(sorted(by_level.items())),
        "top_rules": [
            {"rule_id": rule_id, "count": count}
            for rule_id, count in sorted(by_rule.items(), key=lambda item: (-item[1], item[0]))[:20]
        ],
    }


def _rule_summary(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for rule in bundle.get("selected_rules") or []:
        if not isinstance(rule, dict):
            continue
        package = rule.get("package")
        package_version = rule.get("package_version")
        packages = rule.get("packages") or []
        if package:
            package_label = f"{package} {package_version}".strip()
            packages = [package_label]
        backing_signals = rule.get("backing_signals") or []
        finding_ids = rule.get("finding_ids") or [
            sig.get("finding_id") or sig.get("id")
            for sig in backing_signals
            if isinstance(sig, dict) and (sig.get("finding_id") or sig.get("id"))
        ]
        rows.append(
            {
                "rule_id": rule.get("rule_id") or rule.get("id"),
                "title": rule.get("title") or rule.get("name"),
                "signal_families": rule.get("signal_families") or [],
                "packages": packages,
                "finding_ids": finding_ids,
                "remediation_key": rule.get("remediation_key"),
                "priority_score": rule.get("priority_score"),
                "backing_signal_count": len(backing_signals),
            }
        )
    return rows


def _batch_number(path: Path) -> int:
    match = re.search(r"after-batch-(\d+)", path.name)
    return int(match.group(1)) if match else 0


def _workflow_context() -> dict[str, Any]:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    run_url = f"{server_url}/{repository}/actions/runs/{run_id}" if repository and run_id else ""
    return {
        "provider": "github_actions" if os.environ.get("GITHUB_ACTIONS") == "true" else "local",
        "repository": repository,
        "workflow": os.environ.get("GITHUB_WORKFLOW", ""),
        "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF", ""),
        "job": os.environ.get("GITHUB_JOB", ""),
        "run_id": run_id,
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "run_url": run_url,
        "event_name": os.environ.get("GITHUB_EVENT_NAME", ""),
        "actor": os.environ.get("GITHUB_ACTOR", ""),
        "ref": os.environ.get("GITHUB_REF", ""),
        "sha": os.environ.get("GITHUB_SHA", ""),
        "inputs": {
            "remediate": os.environ.get("REACHABLE_REMEDIATE_ENABLED", ""),
            "rescan_only": os.environ.get("REACHABLE_RESCAN_ONLY", ""),
            "remediation_mode": os.environ.get("REACHABLE_REMEDIATION_MODE", ""),
            "agent": os.environ.get("REACHABLE_AGENT", ""),
            "prompt_agent": os.environ.get("REACHABLE_PROMPT_AGENT", ""),
            "llm_provider": os.environ.get("REACHABLE_LLM_PROVIDER", ""),
            "prompt_profile": os.environ.get("REACHABLE_PROMPT_PROFILE", ""),
            "signal_types": os.environ.get("REACHABLE_SIGNAL_TYPES", ""),
            "max_batches": os.environ.get("REACHABLE_MAX_BATCHES", ""),
            "rescan_strategy": os.environ.get("REACHABLE_RESCAN_STRATEGY", ""),
            "scan_extra_flags": os.environ.get("REACHABLE_SCAN_EXTRA_FLAGS", ""),
            "create_pr": os.environ.get("REACHABLE_CREATE_PR", ""),
        },
        "credential_presence": {
            "reachable_api_key": bool(os.environ.get("REACHABLE_API_KEY")),
            "reachable_github_token": bool(os.environ.get("REACHABLE_GITHUB_TOKEN")),
            "mcp_github_token": bool(os.environ.get("MCP_GITHUB_TOKEN")),
            "anthropic_api_key": bool(os.environ.get("ANTHROPIC_API_KEY")),
            "openai_api_key": bool(os.environ.get("OPENAI_API_KEY")),
        },
    }


def _write_markdown(path: Path, ledger: dict[str, Any]) -> None:
    lines = [
        "# Reachable Remediation Ledger",
        "",
        f"- Created: `{ledger['created_at']}`",
        f"- Mode: `{ledger['remediation_mode']}`",
        f"- Branch: `{ledger['remediation_branch']}`",
        "",
        "## Findings",
        "",
        "| Scan | Compatibility export results | Error | Warning | Note |",
        "|------|---------------|-------|---------|------|",
    ]

    for scan in ledger["scans"]:
        levels = scan.get("by_level") or {}
        lines.append(
            f"| `{scan['label']}` | {scan['results']} | "
            f"{levels.get('error', 0)} | {levels.get('warning', 0)} | {levels.get('note', 0)} |"
        )

    lines.extend(["", "## Attempted Fixes", ""])
    if not ledger["attempts"]:
        lines.append("No remediation prompt was generated in this run.")
    else:
        for attempt in ledger["attempts"]:
            lines.append(
                f"- Batch `{attempt['batch']}`: `{attempt['selected_rule_count']}` selected rule(s), "
                f"agent log `{attempt['agent_log']}`."
            )
            for rule in attempt.get("selected_rules") or []:
                title = rule.get("title") or rule.get("rule_id") or "untitled"
                families = ",".join(str(x) for x in rule.get("signal_families") or [])
                lines.append(f"  - `{rule.get('rule_id')}` {title} ({families})")

    lines.extend(
        [
            "",
            "## Outcome",
            "",
            f"Proof scan: `{(ledger.get('proof_scan') or {}).get('label', 'none')}`",
            "",
            f"Status: **{ledger['outcome']['status']}**",
            "",
            ledger["outcome"]["message"],
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    artifact_dir = Path(sys.argv[1] if len(sys.argv) > 1 else ".reachable/ci-artifacts")
    bundle_path = Path(sys.argv[2] if len(sys.argv) > 2 else ".reachable/remediation-bundle/bundle.json")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    db_persisted = False
    db_error = ""

    scans: list[dict[str, Any]] = []
    baseline = artifact_dir / "reachable.sarif"
    if baseline.exists():
        summary = _sarif_summary(baseline)
        summary["label"] = "baseline"
        scans.append(summary)

    for sarif_path in sorted(artifact_dir.glob("reachable-after-batch-*.sarif"), key=_batch_number):
        summary = _sarif_summary(sarif_path)
        summary["label"] = sarif_path.stem.replace("reachable-", "")
        scans.append(summary)

    final = artifact_dir / "reachable-after-final.sarif"
    if final.exists():
        summary = _sarif_summary(final)
        summary["label"] = "after-final"
        scans.append(summary)

    bundle = _load_json(bundle_path)
    attempts = []
    if bundle:
        batch = len(list(artifact_dir.glob("reachable-after-batch-*.sarif"))) or 1
        agent_log_dir = Path(os.environ.get("REACHABLE_AGENT_LOG_DIR") or ".reachable/private-agent-logs")
        agent_log = agent_log_dir / f"agent-batch-{batch}.log"
        attempts.append(
            {
                "batch": batch,
                "bundle_path": str(bundle_path),
                "selected_rule_count": bundle.get("selected_rule_count")
                or len(bundle.get("selected_rules") or []),
                "selected_rules": _rule_summary(bundle),
                "selected_packages": bundle.get("selected_packages") or [],
                "agent_log": str(agent_log),
                "agent_log_public_artifact": False,
            }
        )

    proof_scan = scans[-1] if scans else {"label": "none", "results": 0}
    rescan_only = str(os.environ.get("REACHABLE_RESCAN_ONLY") or "").lower() == "true"
    if rescan_only:
        if int(proof_scan.get("results") or 0) == 0:
            status = "verified"
            message = (
                f"The `{proof_scan.get('label')}` compatibility export contains no actionable findings. "
                "The demo verdict is still determined by the DB proof gate."
            )
        else:
            status = "verification_failed"
            message = (
                f"The `{proof_scan.get('label')}` compatibility export still contains actionable findings. "
                "Run another remediation batch or send the branch for human review."
            )
    elif not attempts:
        status = "scan_only"
        message = "No remediation was attempted. Review the DB-backed baseline report for current actionable findings."
    elif int(proof_scan.get("results") or 0) == 0:
        status = "success"
        message = (
            f"The `{proof_scan.get('label')}` compatibility export contains no actionable findings. "
            "The demo verdict is still determined by the DB proof gate."
        )
    else:
        status = "needs_retry_or_human_review"
        message = (
            f"The `{proof_scan.get('label')}` compatibility export still contains actionable findings. "
            "Generate another prompt from the updated branch state, or send the branch for human review."
        )

    ledger = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "remediation_run_id": bundle.get("remediation_audit_run_id") if isinstance(bundle, dict) else "",
        "remediation_mode": os.environ.get("REACHABLE_REMEDIATION_MODE", ""),
        "remediation_branch": os.environ.get("REACHABLE_REMEDIATION_BRANCH", ""),
        "workflow": _workflow_context(),
        "scans": scans,
        "proof_scan": proof_scan,
        "attempts": attempts,
        "outcome": {"status": status, "message": message},
    }

    json_path = artifact_dir / "remediation-ledger.json"
    md_path = artifact_dir / "remediation-ledger.md"
    json_path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_markdown(md_path, ledger)
    db_path = Path(str(bundle.get("db_path") or os.environ.get("REACHABLE_REPO_DB") or "")) if isinstance(bundle, dict) else Path("")
    if db_path and str(db_path) != "." and db_path.exists():
        try:
            from reachable.remediation_audit import (
                load_agent_remediation_report,
                materialize_agent_remediation_ledger,
                render_agent_remediation_json,
                render_agent_remediation_markdown,
            )

            run_id = materialize_agent_remediation_ledger(
                db_path=db_path,
                ledger=ledger,
                bundle=bundle if isinstance(bundle, dict) else {},
                artifact_dir=artifact_dir,
            )
            report = load_agent_remediation_report(db_path=db_path, run_id=run_id)
            (artifact_dir / "remediation-ledger-db.json").write_text(
                render_agent_remediation_json(report),
                encoding="utf-8",
            )
            (artifact_dir / "remediation-ledger-db.md").write_text(
                render_agent_remediation_markdown(report),
                encoding="utf-8",
            )
            materialize_agent_remediation_ledger(
                db_path=db_path,
                ledger={**ledger, "remediation_run_id": run_id},
                bundle={**bundle, "remediation_audit_run_id": run_id} if isinstance(bundle, dict) else {},
                artifact_dir=artifact_dir,
            )
            db_persisted = True
            ledger["remediation_run_id"] = run_id
            json_path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            _write_markdown(md_path, ledger)
        except Exception as exc:  # pragma: no cover - CI compatibility fallback
            db_error = str(exc)
            print(f"::warning::Reachable remediation DB ledger persistence failed: {exc}", file=sys.stderr)
    elif attempts or bundle:
        db_error = "repo.db path unavailable; remediation ledger kept as file artifact only"
        print(f"::warning::{db_error}", file=sys.stderr)
    else:
        db_error = "scan-only run; no remediation bundle required DB persistence"

    status_path = artifact_dir / "remediation-ledger-db-status.txt"
    status_path.write_text(
        "\n".join(
            [
                f"db_persisted={str(db_persisted).lower()}",
                f"db_path={db_path if db_path and str(db_path) != '.' else ''}",
                f"error={db_error}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"Reachable remediation ledger written: {json_path}")
    print(f"Reachable remediation ledger written: {md_path}")
    print(f"Reachable remediation ledger DB persistence: {db_persisted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

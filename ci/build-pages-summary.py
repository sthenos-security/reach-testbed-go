#!/usr/bin/env python3
"""Build a public Reachable Pages summary for the demo workflow.

This page is intentionally smaller than the full Reachable dashboard. It is
safe for a public demo repo: DB-backed baseline/fix proof, selected public
SARIF posture, remediation ledger status, and links. It does not publish raw
prompt bundles, agent transcripts, local databases, or private logs.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import shutil
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"error": 0, "warning": 1, "note": 2, "none": 3}
RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
REACHABILITY_ORDER = {"exploitable": 0, "reachable": 1, "unknown": 2, "defended": 3, "defendable": 4}
DEFENDED_STATES = {"DEFENDED", "DEFENDABLE", "NOT_EXPLOITABLE", "SAFE", "SUPPRESSED"}
AI_LLM_TERMS = (
    " ai ",
    " llm",
    "prompt",
    "rag",
    "mcp",
    "model",
    "embedding",
    "agent",
    "tool call",
    "training data",
)
MALWARE_TERMS = ("malware", "malicious", "guarddog", "yara", "suspicious package", "osv malicious")
DLP_TERMS = ("dlp", " pii", "personal data", "sensitive data", "ssn", "credit card", "passport", "email address")
OWASP_WEB_CWE_MAP = {
    "A01 Broken Access Control": {22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275},
    "A02 Cryptographic Failures": {259, 310, 319, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916},
    "A03 Injection": {20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 100, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917, 943},
    "A04 Insecure Design": {209, 256, 501, 522, 525, 602, 656, 657, 799, 807, 840, 841, 927},
    "A05 Security Misconfiguration": {2, 11, 13, 15, 16, 209, 311, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004},
    "A07 Identification and Authentication Failures": {287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940},
    "A08 Software and Data Integrity Failures": {345, 353, 426, 494, 502, 565, 784, 829, 830, 915},
    "A09 Security Logging and Monitoring Failures": {117, 223, 532, 778},
    "A10 Server-Side Request Forgery": {918},
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sarif", default=".reachable/ci-artifacts/reachable-code-scanning.sarif")
    parser.add_argument("--ledger", default=".reachable/ci-artifacts/remediation-ledger.json")
    parser.add_argument("--out", default=".reachable/ci-artifacts/pages")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    sarif_path = Path(args.sarif)
    ledger_path = Path(args.ledger)
    sarif = _load_json(sarif_path) if sarif_path.exists() else {}
    ledger = _load_json(ledger_path) if ledger_path.exists() else {}
    artifacts: list[dict[str, str]] = []
    if sarif_path.exists():
        shutil.copy2(sarif_path, out_dir / "reachable.sarif")
        artifacts.append({"label": "Selected SARIF", "href": "reachable.sarif"})
    if ledger_path.exists():
        shutil.copy2(ledger_path, out_dir / "remediation-ledger.json")
        artifacts.append({"label": "Sanitized remediation ledger", "href": "remediation-ledger.json"})
    expected_doc_path = Path(__file__).resolve().parents[1] / "EXPECTED.md"
    if expected_doc_path.exists():
        shutil.copy2(expected_doc_path, out_dir / "EXPECTED.md")
        artifacts.append({"label": "Expected issue contract", "href": "EXPECTED.md"})
    compliance = _copy_latest_compliance_pack(out_dir)

    summary = _summarize(sarif=sarif, ledger=ledger, compliance=compliance)
    summary["compliance"] = compliance
    summary["artifacts"] = artifacts
    summary["expected_demo"] = _expected_demo_summary(artifact_dir=ledger_path.parent)
    summary["ai_economics"] = _demo_ai_economics(summary["expected_demo"])
    summary["artifacts"].extend(
        [
            {"label": "Summary JSON", "href": "summary.json"},
            {"label": "Summary Markdown", "href": "summary.md"},
        ]
    )
    page_url = _pages_url()
    code_scanning_url = _code_scanning_url()
    run_url = _run_url()

    (out_dir / "index.html").write_text(
        _render_html(
            summary=summary,
            generated_at=datetime.now(timezone.utc).isoformat(),
            page_url=page_url,
            code_scanning_url=code_scanning_url,
            run_url=run_url,
        ),
        encoding="utf-8",
    )
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown = _render_markdown(summary=summary, page_url=page_url, code_scanning_url=code_scanning_url, run_url=run_url)
    (out_dir / "summary.md").write_text(markdown, encoding="utf-8")

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write(markdown)
            handle.write("\n")
    elif os.environ.get("GITLAB_CI"):
        print(markdown)
    return 0


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - CI summary should still render.
        return {"_error": f"failed to parse {path}: {exc}"}


def _load_json_required(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _expected_demo_summary(*, artifact_dir: Path) -> dict[str, Any]:
    expected_path = Path(__file__).resolve().parents[1] / "expected" / "baseline.json"
    if not expected_path.exists():
        raise FileNotFoundError(f"expected demo contract is required: {expected_path}")

    expected = _load_json_required(expected_path)
    expected_rows = [_expected_row(tuple(item)) for item in ((expected.get("sarif") or {}).get("results") or [])]
    baseline_ctx = _scan_db_context(artifact_dir / "reports" / "baseline" / "scan-path.txt")
    after_ctx = _scan_db_context(artifact_dir / "reports" / "after-final" / "scan-path.txt")
    baseline_rows = _db_expected_row_map(baseline_ctx)
    after_rows = _db_expected_row_map(after_ctx)
    after_actionable_total = _db_actionable_count(after_ctx)
    baseline_ai = _db_ai_usage_summary(baseline_ctx)
    after_ai = _db_ai_usage_summary(after_ctx)

    rows: list[dict[str, Any]] = []
    baseline_found = 0
    fixed = 0
    still_present = 0
    missing = 0
    for row in expected_rows:
        key = row["match_key"]
        before_items = baseline_rows.get(key, [])
        after_items = after_rows.get(key, [])
        found_before = bool(before_items)
        found_after = bool(after_items)
        if found_before:
            baseline_found += 1
        else:
            missing += 1
        if found_before and not found_after:
            fixed += 1
            status = "fixed"
            status_label = "Fixed - no longer reported"
        elif found_after:
            still_present += 1
            status = "still_present"
            status_label = "Still present after remediation"
        else:
            status = "baseline_missing"
            status_label = "Expected baseline row was not detected"
        baseline_signal = before_items[0] if before_items else {}
        after_signal = after_items[0] if after_items else {}
        exploitability = _expected_exploitability(row, baseline_signal)
        rows.append(
            {
                **row,
                "found_before": found_before,
                "found_after": found_after,
                "status": status,
                "status_label": status_label,
                "baseline_signal": _public_signal(baseline_signal),
                "after_signal": _public_signal(after_signal),
                "actual_risk": baseline_signal.get("risk_level") or baseline_signal.get("severity") or "",
                "actual_reachability": baseline_signal.get("app_reachability") or "",
                "actual_exploitability": exploitability,
                "remediation_action": baseline_signal.get("remediation_action") or _expected_business_value(row),
                "signal_title": baseline_signal.get("title") or "",
                "signal_description": baseline_signal.get("description") or "",
            }
        )

    expected_total = len(expected_rows)
    clean = still_present == 0 and after_actionable_total == 0
    if clean and baseline_found == expected_total:
        headline = "All expected demo vulnerabilities were found and the remediation branch now scans clean."
    elif still_present == 0:
        headline = "The remediation proof scan is clean, but the baseline contract did not fully match."
    else:
        headline = "The remediation proof scan still has expected findings to review."

    return {
        "available": True,
        "name": expected.get("name") or "reach-testbed-go golden baseline",
        "verified_with_reachable": expected.get("verified_with_reachable") or "",
        "expected_total": expected_total,
        "baseline_found": baseline_found,
        "baseline_missing": missing,
        "fixed": fixed,
        "still_present": still_present,
        "after_available": True,
        "after_total": after_actionable_total,
        "clean": clean,
        "headline": headline,
        "rows": rows,
        "contract_path": "EXPECTED.md",
        "baseline": baseline_ctx["meta"],
        "after": after_ctx["meta"],
        "baseline_ai": baseline_ai,
        "after_ai": after_ai,
        "evidence_source": "repo.db",
    }


def _expected_row(item: tuple[Any, ...]) -> dict[str, Any]:
    rule, reachability, risk, prod, path, line = item
    location = f"{path}:{line}" if line else str(path)
    return {
        "match_key": _expected_match_key(rule, path, line),
        "rule_id": str(rule or ""),
        "expected_reachability": str(reachability or ""),
        "expected_risk": str(risk or ""),
        "prod_status": str(prod or ""),
        "family": _expected_family(rule),
        "path": str(path or ""),
        "line": int(line or 0),
        "location": location,
        "kind": _plain_kind(str(rule or "")),
        "problem_ref": "EXPECTED.md#expected-findings-table",
    }


def _scan_db_context(scan_path_file: Path) -> dict[str, Any]:
    if not scan_path_file.exists():
        raise FileNotFoundError(f"required scan-path file is missing: {scan_path_file}")
    scan_dir = Path(scan_path_file.read_text(encoding="utf-8").strip())
    if not scan_dir.exists():
        raise FileNotFoundError(f"scan directory from {scan_path_file} does not exist: {scan_dir}")
    db_path = scan_dir.parent.parent / "repo.db"
    if not db_path.exists():
        raise FileNotFoundError(f"repo.db is required for demo proof and was not found: {db_path}")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    scan_meta = _scan_meta(conn, scan_dir)
    return {"db_path": db_path, "scan_dir": scan_dir, "scan_id": scan_meta["id"], "meta": scan_meta}


def _scan_meta(conn: sqlite3.Connection, scan_dir: Path) -> dict[str, Any]:
    rows = conn.execute(
        """
        SELECT id, branch, commit_hash, commit_short, scan_dir, timestamp,
               duration_seconds, version, status, total_findings,
               reachable_findings, critical_count, high_count, medium_count,
               low_count, risk_level
          FROM scans
         ORDER BY id DESC
        """
    ).fetchall()
    matches = [dict(row) for row in rows if Path(str(row["scan_dir"] or "")) == scan_dir]
    if not matches:
        raise RuntimeError(f"scan directory {scan_dir} was not found in repo.db scans table")
    meta = matches[0]
    meta["db_scan_id"] = meta["id"]
    meta.pop("scan_dir", None)
    return meta


def _db_expected_row_map(ctx: dict[str, Any]) -> dict[tuple[str, str, int], list[dict[str, Any]]]:
    db_path = Path(ctx["db_path"])
    scan_id = int(ctx["scan_id"])
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    attacker = _attacker_map(conn, scan_id)
    mapped: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    rows = conn.execute(
        """
        SELECT id, signal_type, finding_id, display_id, file_path, line_number,
               severity, title, description, app_reachability, cwe_id, cve_id,
               secret_type, pii_type, package_name, package_version, scanner,
               rule_id, risk_level, prod_status, remediation_kind,
               remediation_target, remediation_action, synthesis_hints_json,
               exploit_verdict_json
          FROM signals
         WHERE scan_id = ?
           AND COALESCE(prod_status, 'UNKNOWN') != 'NON_PROD'
        """,
        (scan_id,),
    ).fetchall()
    for raw in rows:
        row = dict(raw)
        path = _normalize_demo_path(str(row.get("file_path") or ""))
        line = int(row.get("line_number") or 0)
        row["normalized_path"] = path
        row["line_number"] = line
        row["attacker"] = attacker.get((_db_family(row), path, line), {})
        for key in _db_match_keys(row):
            mapped.setdefault(key, []).append(row)
    return mapped


def _public_signal(row: dict[str, Any]) -> dict[str, Any]:
    if not row:
        return {}
    attacker = row.get("attacker") if isinstance(row.get("attacker"), dict) else {}
    public: dict[str, Any] = {
        "id": row.get("id"),
        "signal_type": row.get("signal_type"),
        "finding_id": row.get("finding_id"),
        "display_id": row.get("display_id"),
        "file_path": row.get("normalized_path") or _normalize_demo_path(str(row.get("file_path") or "")),
        "line_number": row.get("line_number"),
        "severity": row.get("severity"),
        "risk_level": row.get("risk_level"),
        "title": row.get("title"),
        "description": row.get("description"),
        "app_reachability": row.get("app_reachability"),
        "prod_status": row.get("prod_status"),
        "cwe_id": row.get("cwe_id"),
        "cve_id": row.get("cve_id"),
        "secret_type": row.get("secret_type"),
        "pii_type": row.get("pii_type"),
        "package_name": row.get("package_name"),
        "package_version": row.get("package_version"),
        "scanner": row.get("scanner"),
        "rule_id": row.get("rule_id"),
        "remediation_kind": row.get("remediation_kind"),
        "remediation_target": row.get("remediation_target"),
        "remediation_action": row.get("remediation_action"),
    }
    if attacker:
        public["attacker"] = {
            "exploitable": attacker.get("exploitable"),
            "severity": attacker.get("severity"),
            "model_used": attacker.get("model_used"),
            "created_at": attacker.get("created_at"),
            "error": attacker.get("error"),
        }
    return {key: value for key, value in public.items() if value not in (None, "")}


def _db_actionable_count(ctx: dict[str, Any]) -> int:
    conn = sqlite3.connect(Path(ctx["db_path"]))
    return int(
        conn.execute(
            """
            SELECT COUNT(*)
              FROM signals
             WHERE scan_id = ?
               AND COALESCE(prod_status, 'UNKNOWN') != 'NON_PROD'
               AND UPPER(COALESCE(app_reachability, 'UNKNOWN')) IN ('EXPLOITABLE', 'REACHABLE', 'UNKNOWN')
               AND COALESCE(risk_level, severity, 'UNKNOWN') NOT IN ('INFO')
            """,
            (int(ctx["scan_id"]),),
        ).fetchone()[0]
        or 0
    )


def _db_ai_usage_summary(ctx: dict[str, Any]) -> dict[str, Any]:
    conn = sqlite3.connect(Path(ctx["db_path"]))
    try:
        row = conn.execute(
            """
            SELECT COUNT(*) AS calls,
                   COALESCE(SUM(CAST(tokens_in AS INTEGER)), 0) AS tokens_in,
                   COALESCE(SUM(CAST(tokens_out AS INTEGER)), 0) AS tokens_out,
                   COALESCE(SUM(CAST(cost_usd AS REAL)), 0.0) AS cost_usd,
                   COALESCE(SUM(CAST(duration_ms AS REAL)), 0.0) AS duration_ms
              FROM enzo_attacker_audit
             WHERE scan_id = ?
            """,
            (int(ctx["scan_id"]),),
        ).fetchone()
    except sqlite3.OperationalError:
        return {"calls": 0, "tokens_in": 0, "tokens_out": 0, "tokens_total": 0, "cost_usd": 0.0, "duration_seconds": 0.0}
    tokens_in = int(row[1] or 0)
    tokens_out = int(row[2] or 0)
    return {
        "calls": int(row[0] or 0),
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "tokens_total": tokens_in + tokens_out,
        "cost_usd": float(row[3] or 0.0),
        "duration_seconds": float(row[4] or 0.0) / 1000.0,
    }


def _attacker_map(conn: sqlite3.Connection, scan_id: int) -> dict[tuple[str, str, int], dict[str, Any]]:
    try:
        rows = conn.execute(
            """
            SELECT finding_type, file_path, line_number, exploitable, severity,
                   attack_vector, defense_rationale, blocked_by_json, model_used,
                   tokens_in, tokens_out, cost_usd, duration_ms, error, created_at
              FROM enzo_attacker_audit
             WHERE scan_id = ?
            """,
            (scan_id,),
        ).fetchall()
    except sqlite3.OperationalError:
        return {}
    out: dict[tuple[str, str, int], dict[str, Any]] = {}
    for raw in rows:
        row = dict(raw)
        family = str(row.get("finding_type") or "").lower()
        if family == "secret":
            family = "secret"
        path = _normalize_demo_path(str(row.get("file_path") or ""))
        try:
            line = int(row.get("line_number") or 0)
        except (TypeError, ValueError):
            line = 0
        out[(family, path, line)] = row
    return out


def _expected_match_key(rule: Any, path: Any, line: Any) -> tuple[str, str, int]:
    return (_expected_family(rule), _normalize_demo_path(str(path or "")), int(line or 0))


def _expected_family(rule: Any) -> str:
    prefix = str(rule or "").split("/", 1)[0].lower()
    return {"secret": "secret", "dlp": "dlp", "ai": "ai", "cwe": "cwe", "cve": "cve"}.get(prefix, prefix or "other")


def _db_family(row: dict[str, Any]) -> str:
    return str(row.get("signal_type") or "").lower()


def _db_match_keys(row: dict[str, Any]) -> set[tuple[str, str, int]]:
    family = _db_family(row)
    path = str(row.get("normalized_path") or _normalize_demo_path(str(row.get("file_path") or "")))
    line = int(row.get("line_number") or 0)
    return {(family, path, line)}


def _expected_exploitability(expected: dict[str, Any], signal: dict[str, Any]) -> str:
    if not signal:
        return ""
    attacker = signal.get("attacker") if isinstance(signal.get("attacker"), dict) else {}
    if attacker:
        if str(attacker.get("error") or "").strip():
            return "ATTACK ERROR"
        exploitable = str(attacker.get("exploitable") or "").strip().lower()
        if exploitable in {"1", "true", "yes", "exploitable"}:
            return "EXPLOITABLE"
        if exploitable in {"0", "false", "no", "not_exploitable", "defended"}:
            return "DEFENDED"
        return "UNCERTAIN"
    expected_state = str(expected.get("expected_reachability") or "").strip().lower()
    return expected_state.upper() if expected_state in {"exploitable", "defended", "defendable"} else "NOT ATTACKED"


def _plain_kind(rule_id: str) -> str:
    if rule_id.startswith("CVE/"):
        return "Vulnerable dependency"
    if rule_id.startswith("CWE/78"):
        return "Command injection"
    if rule_id.startswith("CWE/918"):
        return "Server-side request forgery"
    if rule_id.startswith("CWE/319"):
        return "Cleartext network exposure"
    if rule_id.startswith("CWE/200"):
        return "Information disclosure"
    if rule_id.startswith("SECRET/"):
        return "Secret exposure"
    if rule_id.startswith("DLP/"):
        return "PII / sensitive data exposure"
    if rule_id.startswith("AI/"):
        return "AI / LLM security issue"
    return "Security finding"


def _sarif_row_map(path: Path) -> Counter[tuple[str, str, str, str, str, int]]:
    rows: Counter[tuple[str, str, str, str, str, int]] = Counter()
    if not path.exists():
        return rows
    data = _load_json(path)
    for run in data.get("runs") or []:
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            loc = ((result.get("locations") or [{}])[0].get("physicalLocation") or {})
            artifact = (loc.get("artifactLocation") or {}).get("uri") or ""
            region = loc.get("region") or {}
            props = result.get("properties") or {}
            rows[
                _row_key(
                    result.get("ruleId"),
                    props.get("reachabilityState"),
                    props.get("riskLevel"),
                    props.get("prodStatus"),
                    _normalize_demo_path(str(artifact)),
                    int(region.get("startLine") or 0),
                )
            ] += 1
    return rows


def _row_key(rule: Any, reachability: Any, risk: Any, prod: Any, path: Any, line: Any) -> tuple[str, str, str, str, str, int]:
    return (
        str(rule or ""),
        str(reachability or "").lower(),
        str(risk or "").upper(),
        str(prod or "").upper(),
        _normalize_demo_path(str(path or "")),
        int(line or 0),
    )


def _normalize_demo_path(path: str) -> str:
    for marker in ("/internal/", "/cmd/", "/config/", "/deploy/", "/testdata/"):
        if marker in path:
            return marker.strip("/") + "/" + path.split(marker, 1)[1]
    return path


def _copy_latest_compliance_pack(out_dir: Path) -> dict[str, Any]:
    artifact_root = out_dir.parent
    reports_root = artifact_root / "reports"
    if not reports_root.exists():
        return {"available": False}
    report_dirs = [path for path in reports_root.iterdir() if path.is_dir()]
    preferred = ["after-final", *sorted((path.name for path in report_dirs), reverse=True)]
    for label in preferred:
        report_dir = reports_root / label
        md_path = report_dir / "compliance.md"
        json_path = report_dir / "compliance.json"
        narrative_md_path = report_dir / "compliance-narrative.md"
        narrative_json_path = report_dir / "compliance-narrative.json"
        if not any(path.exists() for path in (md_path, json_path, narrative_md_path, narrative_json_path)):
            continue
        copied: dict[str, Any] = {"available": True, "label": label}
        if md_path.exists():
            shutil.copy2(md_path, out_dir / "compliance.md")
            copied["markdown"] = "compliance.md"
        if json_path.exists():
            shutil.copy2(json_path, out_dir / "compliance.json")
            copied["json"] = "compliance.json"
            compliance_json = _load_json(json_path)
            proof_counts = (compliance_json.get("summary") or {}).get("proof_run_counts")
            if isinstance(proof_counts, dict):
                copied["proof_run_counts"] = proof_counts
        if narrative_md_path.exists():
            shutil.copy2(narrative_md_path, out_dir / "compliance-narrative.md")
            copied["narrative_markdown"] = "compliance-narrative.md"
        if narrative_json_path.exists():
            shutil.copy2(narrative_json_path, out_dir / "compliance-narrative.json")
            copied["narrative_json"] = "compliance-narrative.json"
        return copied
    return {"available": False}


def _summarize(*, sarif: dict[str, Any], ledger: dict[str, Any], compliance: dict[str, Any] | None = None) -> dict[str, Any]:
    run = (sarif.get("runs") or [{}])[0] if isinstance(sarif, dict) else {}
    rules = {
        str(rule.get("id") or ""): rule
        for rule in (((run.get("tool") or {}).get("driver") or {}).get("rules") or [])
        if isinstance(rule, dict)
    }
    results = [item for item in (run.get("results") or []) if isinstance(item, dict)]
    findings = [_result_summary(result, rules.get(str(result.get("ruleId") or ""), {})) for result in results]
    findings.sort(key=_priority_key)
    top_priority = [
        item
        for item in findings
        if item["reachability"].lower() in {"exploitable", "reachable"}
    ][:12]
    if not top_priority:
        top_priority = findings[:12]
    top_defended = [item for item in findings if _is_defended(item)][:12]
    by_family = Counter(family for item in findings for family in item.get("families", []))
    suspicious_package_count = sum(1 for item in findings if _is_suspicious_package(item))

    return {
        "repo": _repo_slug(),
        "ref": os.environ.get("CI_COMMIT_REF_NAME") or os.environ.get("GITHUB_REF_NAME", ""),
        "sha": os.environ.get("CI_COMMIT_SHA") or os.environ.get("GITHUB_SHA", ""),
        "run_id": os.environ.get("CI_PIPELINE_ID") or os.environ.get("GITHUB_RUN_ID", ""),
        "total": len(findings),
        "by_level": dict(Counter(item["level"] for item in findings)),
        "by_type": dict(Counter(item["type"] for item in findings)),
        "by_reachability": dict(Counter(item["reachability"] for item in findings)),
        "by_family": dict(by_family),
        "suspicious_package_count": suspicious_package_count,
        "top_priority": top_priority,
        "top_defended": top_defended,
        "top": findings[:25],
        "remediation": _remediation_summary(ledger),
        "verification": _verification_summary(ledger=ledger, findings=findings),
        "proof": _proof_summary(run=run, findings=findings, compliance=compliance or {}),
        "sarif_error": sarif.get("_error"),
        "ledger_error": ledger.get("_error"),
    }


def _result_summary(result: dict[str, Any], rule: dict[str, Any]) -> dict[str, Any]:
    props = result.get("properties") or {}
    rule_id = str(result.get("ruleId") or rule.get("id") or "REACHABLE")
    prefix = rule_id.split("/", 1)[0] if "/" in rule_id else "OTHER"
    message = str(((result.get("message") or {}).get("text")) or "")
    package = str(props.get("package") or "")
    fix = str(props.get("fixVersion") or props.get("workaround") or "")
    level = str(result.get("level") or "warning").lower()
    title = str(((rule.get("shortDescription") or {}).get("text")) or rule.get("name") or rule_id)
    reachability = _reachability_state(props, message, title)
    risk = _risk_level(props, result, rule)
    families = _families_for_result(rule_id=rule_id, prefix=prefix, title=title, message=message, props=props)
    return {
        "rule_id": rule_id,
        "type": prefix,
        "title": title,
        "message": message,
        "level": level,
        "risk": risk,
        "reachability": reachability,
        "package": package,
        "fix": fix,
        "location": _location(result),
        "families": families,
        "proof": _sanitize_proof_evidence(props.get("proofEvidence")),
    }


def _reachability_state(props: dict[str, Any], message: str, title: str) -> str:
    raw = str(
        props.get("reachabilityState")
        or props.get("state")
        or props.get("attackerOutcome")
        or props.get("attackOutcome")
        or "unknown"
    ).strip()
    normalized = raw.upper().replace("-", "_").replace(" ", "_")
    haystack = f" {title} {message} ".lower()
    if normalized in {"DEFENDED", "DEFENDABLE", "NOT_EXPLOITABLE", "SAFE", "SUPPRESSED"}:
        return "DEFENDED" if normalized in {"NOT_EXPLOITABLE", "SAFE", "SUPPRESSED"} else normalized
    if "not exploitable" in haystack or "blocked by" in haystack or "defended" in haystack:
        return "DEFENDED"
    return normalized or "UNKNOWN"


def _risk_level(props: dict[str, Any], result: dict[str, Any], rule: dict[str, Any]) -> str:
    raw = (
        props.get("riskLevel")
        or props.get("risk")
        or props.get("severity")
        or ((rule.get("properties") or {}).get("severity") if isinstance(rule.get("properties"), dict) else None)
        or result.get("level")
        or "UNKNOWN"
    )
    risk = str(raw).upper().replace("-", "_").replace(" ", "_")
    if risk == "ERROR":
        return "HIGH"
    if risk == "WARNING":
        return "MEDIUM"
    if risk == "NOTE":
        return "LOW"
    return risk


def _families_for_result(*, rule_id: str, prefix: str, title: str, message: str, props: dict[str, Any]) -> list[str]:
    text = f" {rule_id} {prefix} {title} {message} {json.dumps(props, sort_keys=True, default=str)} ".lower()
    families: list[str] = []
    if prefix in {"MALWARE", "SUSPICIOUS"} or any(term in text for term in MALWARE_TERMS):
        families.append("Malware / suspicious supply chain")
    if prefix == "DLP" or any(term in text for term in DLP_TERMS):
        families.append("DLP / PII")
    if prefix in {"AI", "LLM", "MCP", "RAG"} or any(term in text for term in AI_LLM_TERMS):
        families.append("OWASP AI / LLM")
    web_labels = _owasp_web_labels(rule_id, title, message, props)
    if web_labels:
        families.append("OWASP Web Top 10")
        families.extend(web_labels[:2])
    if prefix == "CVE":
        families.append("OWASP Web Top 10")
        families.append("A06 Vulnerable and Outdated Components")
    if prefix == "SECRET":
        families.append("Secrets")
    return sorted(dict.fromkeys(families))


def _owasp_web_labels(rule_id: str, title: str, message: str, props: dict[str, Any]) -> list[str]:
    text = f" {rule_id} {title} {message} {json.dumps(props, sort_keys=True, default=str)} "
    cwes = {int(match) for match in re.findall(r"CWE[-_ ]?(\d+)", text, flags=re.IGNORECASE)}
    return [label for label, members in OWASP_WEB_CWE_MAP.items() if cwes & members]


def _is_defended(item: dict[str, Any]) -> bool:
    return str(item.get("reachability") or "").upper() in DEFENDED_STATES


def _is_suspicious_package(item: dict[str, Any]) -> bool:
    rule_id = str(item.get("rule_id") or "").upper()
    return item.get("type") == "SUSPICIOUS" or rule_id.startswith("SUSPICIOUS/")


def _location(result: dict[str, Any]) -> str:
    locations = result.get("locations") or []
    if not locations:
        return ""
    physical = ((locations[0].get("physicalLocation") or {}) if isinstance(locations[0], dict) else {})
    uri = str(((physical.get("artifactLocation") or {}).get("uri")) or "")
    region = physical.get("region") or {}
    line = region.get("startLine")
    return f"{uri}:{line}" if uri and line else uri


def _priority_key(item: dict[str, str]) -> tuple[int, int, str, str]:
    return (
        REACHABILITY_ORDER.get(item["reachability"].lower(), 9),
        RISK_ORDER.get(item.get("risk", "UNKNOWN").upper(), 9),
        item["type"],
        item["rule_id"],
    )


def _remediation_summary(ledger: dict[str, Any]) -> dict[str, Any]:
    if not ledger:
        return {"status": "not-run", "message": "No remediation ledger was produced."}
    outcome = ledger.get("outcome") if isinstance(ledger.get("outcome"), dict) else {}
    attempts = ledger.get("attempts") or []
    scans = ledger.get("scans") or []
    selected_rules = []
    for attempt in attempts:
        if isinstance(attempt, dict):
            selected_rules.extend(attempt.get("selected_rules") or [])
    return {
        "status": outcome.get("status") or ledger.get("status") or "unknown",
        "message": outcome.get("message") or ledger.get("message") or "",
        "attempt_count": len(attempts),
        "scan_count": len(scans),
        "proof_scan": ledger.get("proof_scan") or {},
        "selected_rule_count": len(selected_rules),
        "selected_rules": selected_rules[:12],
    }


def _verification_summary(*, ledger: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    if not ledger:
        return {
            "status": "not-run",
            "mode": "none",
            "clean": len(findings) == 0,
            "results": len(findings),
            "label": "selected-sarif",
            "message": "No remediation ledger was produced.",
        }
    outcome = ledger.get("outcome") if isinstance(ledger.get("outcome"), dict) else {}
    workflow = ledger.get("workflow") if isinstance(ledger.get("workflow"), dict) else {}
    inputs = workflow.get("inputs") if isinstance(workflow.get("inputs"), dict) else {}
    proof_scan = ledger.get("proof_scan") if isinstance(ledger.get("proof_scan"), dict) else {}
    results = _safe_int(proof_scan.get("results") if proof_scan else len(findings))
    rescan_only = str(inputs.get("rescan_only") or "").lower() == "true"
    remediation_enabled = str(inputs.get("remediate") or "").lower() == "true"
    if rescan_only:
        mode = "rescan-only branch verification"
    elif remediation_enabled:
        mode = "automatic post-remediation proof"
    else:
        mode = "scan-only baseline"
    status = str(outcome.get("status") or "unknown")
    return {
        "status": status,
        "mode": mode,
        "clean": results == 0,
        "results": results,
        "label": str(proof_scan.get("label") or "selected-sarif"),
        "message": str(outcome.get("message") or ""),
        "branch": str(ledger.get("remediation_branch") or workflow.get("ref") or ""),
        "run_url": str(workflow.get("run_url") or ""),
    }


def _proof_summary(*, run: dict[str, Any], findings: list[dict[str, Any]], compliance: dict[str, Any]) -> dict[str, Any]:
    proof = _sanitize_proof_evidence((run.get("properties") or {}).get("proofEvidence"))
    source = "sarif" if proof.get("run_count") else ""
    if not proof.get("run_count"):
        proof = _proof_from_compliance_counts(compliance.get("proof_run_counts"))
        source = "compliance" if proof.get("run_count") else ""
    if not proof.get("run_count"):
        proof = _proof_from_findings(findings)
        source = "sarif-results" if proof.get("run_count") else "none"
    proof["source"] = source
    return proof


def _sanitize_proof_evidence(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return _empty_proof_summary()
    return {
        "profile_count": _safe_int(value.get("profileCount")),
        "run_count": _safe_int(value.get("runCount")),
        "verified_exploitable": _safe_int(value.get("verifiedExploitable")),
        "defended_after_reattack": _safe_int(value.get("defendedAfterReattack")),
        "needs_review": _safe_int(value.get("needsReview")),
        "failed": _safe_int(value.get("failed")),
        "skipped_policy": _safe_int(value.get("skippedPolicy")),
        "by_state": _safe_int_map(value.get("byState")),
        "profile_kinds": [str(item) for item in (value.get("profileKinds") or []) if item],
    }


def _proof_from_compliance_counts(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return _empty_proof_summary()
    return {
        "profile_count": _safe_int(value.get("total_profiles")),
        "run_count": _safe_int(value.get("total_runs")),
        "verified_exploitable": _safe_int(value.get("verified_exploitable")),
        "defended_after_reattack": _safe_int(value.get("defended_after_reattack")),
        "needs_review": _safe_int(value.get("needs_review")),
        "failed": _safe_int(value.get("failed")),
        "skipped_policy": _safe_int(value.get("skipped_policy")),
        "by_state": _safe_int_map(value.get("by_state")),
        "profile_kinds": sorted(str(item) for item in (value.get("by_profile_kind") or {}).keys() if item),
    }


def _proof_from_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    summary = _empty_proof_summary()
    kinds: set[str] = set()
    for item in findings:
        proof = item.get("proof")
        if not isinstance(proof, dict) or not proof.get("run_count"):
            continue
        summary["profile_count"] += _safe_int(proof.get("profile_count"))
        summary["run_count"] += _safe_int(proof.get("run_count"))
        summary["verified_exploitable"] += _safe_int(proof.get("verified_exploitable"))
        summary["defended_after_reattack"] += _safe_int(proof.get("defended_after_reattack"))
        summary["needs_review"] += _safe_int(proof.get("needs_review"))
        summary["failed"] += _safe_int(proof.get("failed"))
        summary["skipped_policy"] += _safe_int(proof.get("skipped_policy"))
        for state, count in (proof.get("by_state") or {}).items():
            summary["by_state"][state] = summary["by_state"].get(state, 0) + _safe_int(count)
        kinds.update(str(kind) for kind in (proof.get("profile_kinds") or []) if kind)
    summary["profile_kinds"] = sorted(kinds)
    return summary


def _empty_proof_summary() -> dict[str, Any]:
    return {
        "profile_count": 0,
        "run_count": 0,
        "verified_exploitable": 0,
        "defended_after_reattack": 0,
        "needs_review": 0,
        "failed": 0,
        "skipped_policy": 0,
        "by_state": {},
        "profile_kinds": [],
    }


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _safe_int_map(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    return {str(key): _safe_int(count) for key, count in value.items() if key}


def _render_html(*, summary: dict[str, Any], generated_at: str, page_url: str, code_scanning_url: str, run_url: str) -> str:
    by_reach = summary.get("by_reachability") or {}
    by_type = summary.get("by_type") or {}
    by_family = summary.get("by_family") or {}
    remediation = summary.get("remediation") or {}
    verification = summary.get("verification") or {}
    compliance = summary.get("compliance") or {}
    proof = summary.get("proof") or {}
    expected_demo = summary.get("expected_demo") or {}
    defended_count = sum(int(by_reach.get(state, 0)) for state in DEFENDED_STATES)
    suspicious_count = int(summary.get("suspicious_package_count") or 0)
    priority_rows = "\n".join(_issue_row(item) for item in summary.get("top_priority") or [])
    if not priority_rows:
        priority_rows = '<tr><td colspan="8">No exploitable or reachable findings were reported.</td></tr>'
    defended_rows = "\n".join(_issue_row(item) for item in summary.get("top_defended") or [])
    if not defended_rows:
        defended_rows = '<tr><td colspan="8">No defended or defendable findings were included in this public SARIF.</td></tr>'
    rows = "\n".join(_issue_row(item) for item in summary.get("top") or [])
    if not rows:
        rows = '<tr><td colspan="8">No production actionable signals were reported.</td></tr>'
    rule_rows = "\n".join(_rule_row(item) for item in remediation.get("selected_rules") or [])
    if not rule_rows:
        rule_rows = '<tr><td colspan="4">No remediation rules were selected in this run.</td></tr>'
    expected_rows = "\n".join(_expected_demo_row(item) for item in expected_demo.get("rows") or [])
    if not expected_rows:
        expected_rows = '<tr><td colspan="9">No checked-in expected baseline contract was found.</td></tr>'
    artifact_links = _artifact_links(summary.get("artifacts") or [], compliance)
    expected_status = "Clean" if expected_demo.get("clean") else "Needs review"
    baseline_meta = expected_demo.get("baseline") if isinstance(expected_demo.get("baseline"), dict) else {}
    after_meta = expected_demo.get("after") if isinstance(expected_demo.get("after"), dict) else {}
    baseline_ai = expected_demo.get("baseline_ai") if isinstance(expected_demo.get("baseline_ai"), dict) else {}
    after_ai = expected_demo.get("after_ai") if isinstance(expected_demo.get("after_ai"), dict) else {}
    ai_economics = summary.get("ai_economics") if isinstance(summary.get("ai_economics"), dict) else {}
    expected_class = "ok" if expected_demo.get("clean") else "bad"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Reachable Go Demo - Last Scan</title>
  <style>
    :root {{ color-scheme: light dark; --bg:#0e151c; --fg:#f7fafc; --muted:#98a7b5; --line:#253342; --card:#141f29; --accent:#5fe0a3; --warn:#ffd166; --bad:#ff7b7b; }}
    body {{ margin:0; font-family:Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:var(--bg); color:var(--fg); }}
    main {{ max-width:1220px; margin:0 auto; padding:32px 20px 48px; }}
    h1 {{ margin:0 0 8px; font-size:32px; letter-spacing:0; }}
    h2 {{ margin:32px 0 12px; font-size:20px; }}
    p {{ color:var(--muted); line-height:1.5; }}
    a {{ color:var(--accent); }}
    .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; margin:24px 0; }}
    .card {{ background:var(--card); border:1px solid var(--line); border-radius:8px; padding:16px; }}
    .hero {{ border:1px solid var(--line); border-radius:8px; padding:22px; background:#101923; }}
    .hero.ok {{ border-color:rgba(95,224,163,.55); }}
    .hero.bad {{ border-color:rgba(255,123,123,.65); }}
    .hero h1 {{ font-size:34px; }}
    .subgrid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(270px,1fr)); gap:12px; margin-top:16px; }}
    .status {{ font-size:13px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); }}
    .status.ok {{ color:var(--accent); }}
    .status.bad {{ color:var(--bad); }}
    .num {{ font-size:28px; font-weight:750; }}
    .label {{ color:var(--muted); font-size:13px; margin-top:4px; }}
    .links {{ display:flex; flex-wrap:wrap; gap:10px; margin:18px 0 4px; }}
    .links a {{ border:1px solid var(--line); border-radius:6px; padding:8px 10px; text-decoration:none; background:#101923; }}
    .artifact-list {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:8px; font-size:12px; }}
    .artifact-list a {{ display:block; border:1px solid var(--line); border-radius:6px; padding:8px 10px; text-decoration:none; background:#101923; }}
    .tabs {{ display:flex; flex-wrap:wrap; gap:8px; margin:18px 0 22px; }}
    .tabs a {{ border:1px solid var(--line); border-radius:999px; padding:8px 12px; text-decoration:none; background:#101923; color:var(--fg); }}
    .tabs a:hover {{ border-color:var(--accent); color:var(--accent); }}
    table {{ width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); border-radius:8px; overflow:hidden; }}
    th, td {{ padding:10px 12px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; font-size:14px; }}
    th {{ color:#dce7ee; background:#111b26; }}
    .muted {{ color:var(--muted); }}
    .pill {{ display:inline-block; border:1px solid var(--line); border-radius:999px; padding:2px 8px; font-size:12px; }}
    .reachable {{ color:var(--accent); }}
    .warning {{ color:var(--warn); }}
    .bad {{ color:var(--bad); }}
    details p {{ margin:8px 0 0; }}
    code {{ word-break:break-word; }}
  </style>
</head>
<body>
  <main>
    <section class="hero {expected_class}">
      <div class="status {expected_class}">Reachable self-remediation demo</div>
      <h1>{html.escape(str(expected_demo.get("headline") or "Reachable Go Demo"))}</h1>
      <p>Public, sanitized proof for the intentionally vulnerable Reachable Go testbed. The page is built from the Reachable scan database: vulnerable baseline scan, remediation proof scan, expected issue contract, branch, commit, scan number, timestamp, and AI cost telemetry. Private prompts, rules, agent transcripts, and local databases are not published.</p>
      <div class="cards">
        {_card("Expected issues", str(expected_demo.get("expected_total", 0)))}
        {_card("Found on vulnerable main", str(expected_demo.get("baseline_found", 0)))}
        {_card("Fixed on remediation branch", str(expected_demo.get("fixed", 0)))}
        {_card("Still present", str(expected_demo.get("still_present", 0)))}
        {_card("Final actionable findings", str(expected_demo.get("after_total") if expected_demo.get("after_total") is not None else "not run"))}
        {_card("AI cost estimate", _money(ai_economics.get("cost_usd")))}
        {_card("AI tokens", _number(ai_economics.get("tokens_total")))}
        {_card("Engineer baseline", _money(ai_economics.get("engineer_baseline_usd")))}
        {_card("Reachable plan", _money(ai_economics.get("reachable_plan_cost_usd")))}
      </div>
      <div class="subgrid">
        {_proof_panel("Vulnerable baseline", baseline_meta, baseline_ai)}
        {_proof_panel("Remediated branch proof", after_meta, after_ai)}
      </div>
    </section>
    <nav class="tabs" aria-label="Reachable report sections">
      <a href="#expected">Expected Fix Proof</a>
      <a href="#findings">Remaining Findings</a>
      <a href="#defended">Defended</a>
      <a href="#remediation">Remediation</a>
      <a href="#artifacts">Artifacts</a>
    </nav>
    <section class="card">
      <h2 id="expected">Demo Contract: Expected Vulnerabilities Fixed</h2>
      <p><strong>{html.escape(expected_status)}:</strong> This table is the demo contract. Each row is an expected vulnerable fixture. “Fixed” means it was present in the vulnerable baseline database and absent from the remediation proof database.</p>
      <table>
        <thead><tr><th>Expected issue</th><th>Risk</th><th>Reachability</th><th>Exploitability</th><th>Location</th><th>Baseline</th><th>Remediation proof</th><th>Status</th><th>Fix / evidence</th></tr></thead>
        <tbody>{expected_rows}</tbody>
      </table>
    </section>
    <h2 id="findings">Remaining Production Actionable Findings</h2>
    <div class="cards">
      {_card("Selected public findings", str(summary.get("total", 0)))}
      {_card("Exploitable", str(by_reach.get("EXPLOITABLE", 0)))}
      {_card("Reachable", str(by_reach.get("REACHABLE", 0)))}
      {_card("Unknown", str(by_reach.get("UNKNOWN", 0)))}
      {_card("Defended", str(defended_count))}
      {_card("Suspicious packages", str(suspicious_count))}
    </div>
    <p class="muted">This section is the selected public posture export for code-scanning surfaces. The demo pass/fail proof above is DB-backed.</p>
    <table>
      <thead><tr><th>Signal</th><th>Reachability</th><th>Risk</th><th>Families</th><th>Package</th><th>Fix</th><th>Location</th><th>Message</th></tr></thead>
      <tbody>{priority_rows}</tbody>
    </table>
    <h2 id="defended">Production Actionable: Defended / Defendable</h2>
    <table>
      <thead><tr><th>Signal</th><th>Reachability</th><th>Risk</th><th>Families</th><th>Package</th><th>Fix</th><th>Location</th><th>Message</th></tr></thead>
      <tbody>{defended_rows}</tbody>
    </table>
    <h2>All Production Actionable Signals</h2>
    <table>
      <thead><tr><th>Signal</th><th>Reachability</th><th>Risk</th><th>Families</th><th>Package</th><th>Fix</th><th>Location</th><th>Message</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
    <h2 id="remediation">Remediation Attempt</h2>
    <p>Status: <strong>{html.escape(str(remediation.get("status") or "unknown"))}</strong>. {html.escape(str(remediation.get("message") or ""))}</p>
    <table>
      <thead><tr><th>Rule</th><th>Package</th><th>Signals</th><th>Suggested fix</th></tr></thead>
      <tbody>{rule_rows}</tbody>
    </table>
    <h2 id="artifacts">Sanitized Artifacts</h2>
    <p class="muted">These are convenience exports. The public page does not publish the private remediation bundle, prompt text, generated rules, agent transcript, raw witnesses, or local databases.</p>
    <div class="artifact-list">{artifact_links}</div>
    <p class="muted">Generated at {html.escape(generated_at)} for {html.escape(str(summary.get("repo") or ""))} / {html.escape(str(summary.get("ref") or ""))} / commit {html.escape(str(summary.get("sha") or ""))}. Page URL: {html.escape(page_url)}</p>
  </main>
</body>
</html>
"""


def _card(label: str, value: str) -> str:
    return f'<div class="card"><div class="num">{html.escape(value)}</div><div class="label">{html.escape(label)}</div></div>'


def _proof_panel(title: str, meta: dict[str, Any], ai: dict[str, Any]) -> str:
    commit = str(meta.get("commit_short") or str(meta.get("commit_hash") or "")[:12])
    duration = _duration(float(meta.get("duration_seconds") or 0))
    ai_tokens = int(ai.get("tokens_total") or 0)
    ai_calls = int(ai.get("calls") or 0)
    ai_cost = _money(float(ai.get("cost_usd") or 0.0))
    return (
        '<div class="card">'
        f"<h2>{html.escape(title)}</h2>"
        f"<p><strong>Scan:</strong> {html.escape(_scan_label(meta))}<br>"
        f"<strong>Branch:</strong> {html.escape(str(meta.get('branch') or ''))}<br>"
        f"<strong>Commit:</strong> <code>{html.escape(commit)}</code><br>"
        f"<strong>Timestamp:</strong> {html.escape(str(meta.get('timestamp') or ''))}<br>"
        f"<strong>Runtime:</strong> {html.escape(duration)}<br>"
        f"<strong>AI:</strong> {ai_calls} calls, {ai_tokens:,} tokens, {html.escape(ai_cost)}</p>"
        "</div>"
    )


def _demo_ai_economics(expected_demo: dict[str, Any]) -> dict[str, Any]:
    baseline_ai = expected_demo.get("baseline_ai") if isinstance(expected_demo.get("baseline_ai"), dict) else {}
    after_ai = expected_demo.get("after_ai") if isinstance(expected_demo.get("after_ai"), dict) else {}
    cost = float(baseline_ai.get("cost_usd") or 0.0) + float(after_ai.get("cost_usd") or 0.0)
    tokens = int(baseline_ai.get("tokens_total") or 0) + int(after_ai.get("tokens_total") or 0)
    calls = int(baseline_ai.get("calls") or 0) + int(after_ai.get("calls") or 0)
    engineer_rate = _env_float("REACHABLE_ENGINEER_HOURLY_USD", 250.0)
    engineer_hours = _env_float("REACHABLE_ENGINEER_HOURS_AVOIDED", 4.0)
    plan_cost = _env_float("REACHABLE_PLAN_COST_USD", 99.0)
    return {
        "source": "repo.db/enzo_attacker_audit",
        "estimated": True,
        "calls": calls,
        "tokens_total": tokens,
        "cost_usd": cost,
        "engineer_hourly_usd": engineer_rate,
        "engineer_hours_avoided": engineer_hours,
        "engineer_baseline_usd": engineer_rate * engineer_hours,
        "reachable_plan_cost_usd": plan_cost,
    }


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _scan_label(meta: dict[str, Any]) -> str:
    if not meta:
        return ""
    scan_id = meta.get("id") or meta.get("db_scan_id") or ""
    version = meta.get("version") or ""
    status = meta.get("status") or ""
    return f"#{scan_id} {version} {status}".strip()


def _money(value: float | int | None) -> str:
    amount = float(value or 0.0)
    return f"${amount:.4f}" if amount < 1 else f"${amount:,.2f}"


def _number(value: Any) -> str:
    try:
        return f"{int(value or 0):,}"
    except (TypeError, ValueError):
        return "0"


def _duration(seconds: float | int | None) -> str:
    total = int(float(seconds or 0))
    if total <= 0:
        return "n/a"
    minutes, sec = divmod(total, 60)
    if minutes:
        return f"{minutes}m {sec}s"
    return f"{sec}s"


def _compliance_links(compliance: dict[str, Any]) -> str:
    if not compliance.get("available"):
        return ""
    links = []
    if compliance.get("markdown"):
        links.append('<a href="compliance.md">Download compliance pack</a>')
    if compliance.get("json"):
        links.append('<a href="compliance.json">Download compliance JSON</a>')
    if compliance.get("narrative_markdown"):
        links.append('<a href="compliance-narrative.md">Download auditor narrative</a>')
    if compliance.get("narrative_json"):
        links.append('<a href="compliance-narrative.json">Download narrative JSON</a>')
    return "\n      ".join(links)


def _artifact_links(artifacts: list[dict[str, str]], compliance: dict[str, Any]) -> str:
    candidates = [
        ("Code scanning alerts", _code_scanning_url(), True),
        ("CI run", _run_url(), True),
        *[(item.get("label", ""), item.get("href", ""), True) for item in artifacts if isinstance(item, dict)],
        ("Compliance pack", "compliance.md", bool(compliance.get("markdown"))),
        ("Compliance JSON", "compliance.json", bool(compliance.get("json"))),
        ("Auditor narrative", "compliance-narrative.md", bool(compliance.get("narrative_markdown"))),
        ("Auditor narrative JSON", "compliance-narrative.json", bool(compliance.get("narrative_json"))),
    ]
    links = [
        f'<a href="{html.escape(url)}">{html.escape(label)}</a>'
        for label, url, available in candidates
        if available and url
    ]
    return "\n      ".join(links) or '<span class="muted">No downloadable sanitized artifacts were created.</span>'


def _issue_row(item: dict[str, str]) -> str:
    reachability = item.get("reachability", "")
    reach_class = "reachable" if reachability in {"REACHABLE", "EXPLOITABLE"} else "defended" if reachability in DEFENDED_STATES else ""
    risk_class = "warning" if item.get("risk") in {"HIGH", "MEDIUM"} else ""
    families = " ".join(f'<span class="pill">{html.escape(str(family))}</span>' for family in item.get("families", [])[:3])
    return (
        "<tr>"
        f"<td><code>{html.escape(item.get('rule_id', ''))}</code></td>"
        f"<td><span class=\"pill {reach_class}\">{html.escape(item.get('reachability', ''))}</span></td>"
        f"<td><span class=\"{risk_class}\">{html.escape(item.get('risk', ''))}</span></td>"
        f"<td>{families}</td>"
        f"<td>{html.escape(item.get('package', ''))}</td>"
        f"<td>{html.escape(item.get('fix', ''))}</td>"
        f"<td><code>{html.escape(item.get('location', ''))}</code></td>"
        f"<td>{html.escape(item.get('message', ''))}</td>"
        "</tr>"
    )


def _expected_demo_row(item: dict[str, Any]) -> str:
    status = str(item.get("status") or "")
    status_label = str(item.get("status_label") or status)
    status_class = "reachable" if status == "fixed" else "warning" if status in {"still_present", "baseline_missing"} else ""
    baseline = "Found" if item.get("found_before") else "Missing"
    after = "Still reported" if item.get("found_after") else "Not reported"
    actual_risk = str(item.get("actual_risk") or item.get("expected_risk") or "")
    actual_reach = str(item.get("actual_reachability") or item.get("expected_reachability") or "")
    exploitability = str(item.get("actual_exploitability") or "")
    title = str(item.get("signal_title") or item.get("kind") or "Security finding")
    details = str(item.get("signal_description") or "")
    remediation_action = str(item.get("remediation_action") or _expected_business_value(item))
    problem_ref = str(item.get("problem_ref") or "EXPECTED.md#expected-findings-table")
    detail_html = ""
    if details:
        detail_html = f"<details><summary>Details</summary><p>{html.escape(details)}</p></details>"
    return (
        "<tr>"
        f"<td><code>{html.escape(str(item.get('rule_id') or ''))}</code><br><span class=\"muted\">{html.escape(title)}</span><br><a href=\"{html.escape(problem_ref)}\">Problem contract</a></td>"
        f"<td>{html.escape(actual_risk)}</td>"
        f"<td>{html.escape(actual_reach)}</td>"
        f"<td>{html.escape(exploitability)}</td>"
        f"<td><code>{html.escape(str(item.get('location') or ''))}</code></td>"
        f"<td>{html.escape(baseline)}</td>"
        f"<td>{html.escape(after)}</td>"
        f"<td><span class=\"pill {status_class}\">{html.escape(status_label)}</span></td>"
        f"<td>{html.escape(remediation_action)}{detail_html}</td>"
        "</tr>"
    )


def _expected_business_value(item: dict[str, Any]) -> str:
    rule_id = str(item.get("rule_id") or "")
    if rule_id.startswith("CVE/"):
        return "Dependency risk removed or upgraded; build manager no longer has to chase the vulnerable library manually."
    if rule_id.startswith("CWE/78"):
        return "Agent removed command-execution risk and proof scan confirms the sink is gone."
    if rule_id.startswith("CWE/918"):
        return "Agent removed arbitrary outbound fetch behavior that could become SSRF."
    if rule_id.startswith("CWE/200"):
        return "Internal error details are no longer exposed to callers where remediation applied."
    if rule_id.startswith("SECRET/"):
        return "Synthetic secret exposure is removed from production-actionable posture."
    if rule_id.startswith("DLP/"):
        return "Synthetic PII exposure is removed from logs or outbound data paths."
    if rule_id.startswith("AI/"):
        return "AI/LLM unsafe data flow is removed or covered by the underlying code fix."
    return "Expected vulnerable fixture row is no longer present in the proof scan."


def _rule_row(item: dict[str, Any]) -> str:
    signals = ", ".join(str(value) for value in (item.get("finding_ids") or item.get("backing_signals") or [])[:6])
    return (
        "<tr>"
        f"<td><code>{html.escape(str(item.get('rule_id') or item.get('remediation_key') or ''))}</code></td>"
        f"<td>{html.escape(str(item.get('package') or ''))}</td>"
        f"<td>{html.escape(signals)}</td>"
        f"<td>{html.escape(str(item.get('suggested_fix') or item.get('status') or ''))}</td>"
        "</tr>"
    )


def _render_markdown(*, summary: dict[str, Any], page_url: str, code_scanning_url: str, run_url: str) -> str:
    by_reach = summary.get("by_reachability") or {}
    by_type = summary.get("by_type") or {}
    by_family = summary.get("by_family") or {}
    remediation = summary.get("remediation") or {}
    verification = summary.get("verification") or {}
    compliance = summary.get("compliance") or {}
    proof = summary.get("proof") or {}
    defended_count = sum(int(by_reach.get(state, 0)) for state in DEFENDED_STATES)
    suspicious_count = int(summary.get("suspicious_package_count") or 0)
    lines = [
        "## Reachable Go Demo - Last Scan",
        "",
        f"- Production actionable signals in selected SARIF: `{summary.get('total', 0)}`",
        f"- Exploitable: `{by_reach.get('EXPLOITABLE', 0)}`",
        f"- Reachable: `{by_reach.get('REACHABLE', 0)}`",
        f"- Unknown: `{by_reach.get('UNKNOWN', 0)}`",
        f"- Defended / defendable: `{defended_count}`",
        f"- CVE: `{by_type.get('CVE', 0)}`",
        f"- CWE: `{by_type.get('CWE', 0)}`",
        f"- Secret: `{by_type.get('SECRET', 0)}`",
        f"- Malware: `{by_type.get('MALWARE', 0)}`",
        f"- Suspicious packages: `{suspicious_count}`",
        f"- DLP / PII: `{by_family.get('DLP / PII', 0)}`",
        f"- OWASP Web Top 10: `{by_family.get('OWASP Web Top 10', 0)}`",
        f"- OWASP AI / LLM: `{by_family.get('OWASP AI / LLM', 0)}`",
        f"- Proof runs: `{proof.get('run_count', 0)}` from `{proof.get('source', 'none')}`",
        f"- Verified proof runs: `{proof.get('verified_exploitable', 0)}`",
        f"- Defended re-attacks: `{proof.get('defended_after_reattack', 0)}`",
        f"- Proof needs review: `{proof.get('needs_review', 0)}`",
        f"- Verification status: `{verification.get('status', 'unknown')}`",
        f"- Verification mode: `{verification.get('mode', 'unknown')}`",
        f"- Verification proof scan: `{verification.get('label', 'selected-sarif')}`",
        f"- Verification remaining SARIF results: `{verification.get('results', 0)}`",
        f"- Remediation status: `{remediation.get('status', 'unknown')}`",
        f"- Compliance evidence pack: `{('available from Pages' if compliance.get('available') else 'not available')}`",
        f"- Compliance narrative draft: `{('available from Pages' if compliance.get('narrative_markdown') else 'not available')}`",
        f"- Pages summary: {page_url or 'available after Pages deployment'}",
        f"- Security dashboard: {code_scanning_url}",
        f"- CI run: {run_url}",
        "",
        "### Production actionable: exploitable / reachable",
        "",
    ]
    for item in (summary.get("top_priority") or [])[:10]:
        suffix = f" fix `{item['fix']}`" if item.get("fix") else ""
        location = f" at `{item['location']}`" if item.get("location") else ""
        lines.append(f"- `{item['rule_id']}` {item['reachability']} risk `{item['risk']}`{suffix}{location}")
    if not (summary.get("top_priority") or []):
        lines.append("- No exploitable or reachable findings were reported.")
    lines.extend(["", "### Production actionable: defended / defendable", ""])
    for item in (summary.get("top_defended") or [])[:10]:
        location = f" at `{item['location']}`" if item.get("location") else ""
        lines.append(f"- `{item['rule_id']}` {item['reachability']} risk `{item['risk']}`{location}")
    if not (summary.get("top_defended") or []):
        lines.append("- No defended or defendable findings were included in this public SARIF.")
    return "\n".join(lines) + "\n"


def _code_scanning_url() -> str:
    if os.environ.get("GITLAB_CI"):
        project_url = os.environ.get("CI_PROJECT_URL", "").rstrip("/")
        return f"{project_url}/-/security/vulnerability_report" if project_url else ""
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    return f"{server}/{repo}/security/code-scanning?query=category%3Areachable" if repo else ""


def _run_url() -> str:
    if os.environ.get("GITLAB_CI"):
        return os.environ.get("CI_PIPELINE_URL", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    return f"{server}/{repo}/actions/runs/{run_id}" if repo and run_id else ""


def _pages_url() -> str:
    pages_url = os.environ.get("CI_PAGES_URL", "")
    if pages_url:
        return pages_url.rstrip("/") + "/"
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repo:
        return ""
    owner, name = repo.split("/", 1)
    return f"https://{owner}.github.io/{name}/"


def _repo_slug() -> str:
    return os.environ.get("CI_PROJECT_PATH") or os.environ.get("GITHUB_REPOSITORY", "")


if __name__ == "__main__":
    raise SystemExit(main())

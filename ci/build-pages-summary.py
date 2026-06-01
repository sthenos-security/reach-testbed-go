#!/usr/bin/env python3
"""Build a public Reachable Pages summary for the demo workflow.

This page is intentionally smaller than the full Reachable dashboard. It is
safe for a public demo repo: SARIF posture, top exploitable/reachable issues,
remediation ledger status, and links. It does not publish raw prompt bundles,
agent transcripts, local databases, or private logs.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import shutil
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
    if sarif_path.exists():
        shutil.copy2(sarif_path, out_dir / "reachable.sarif")
    if ledger_path.exists():
        shutil.copy2(ledger_path, out_dir / "remediation-ledger.json")
    compliance = _copy_latest_compliance_pack(out_dir)

    summary = _summarize(sarif=sarif, ledger=ledger)
    summary["compliance"] = compliance
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
    return 0


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - CI summary should still render.
        return {"_error": f"failed to parse {path}: {exc}"}


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
        if not md_path.exists() and not json_path.exists():
            continue
        copied: dict[str, Any] = {"available": True, "label": label}
        if md_path.exists():
            shutil.copy2(md_path, out_dir / "compliance.md")
            copied["markdown"] = "compliance.md"
        if json_path.exists():
            shutil.copy2(json_path, out_dir / "compliance.json")
            copied["json"] = "compliance.json"
        return copied
    return {"available": False}


def _summarize(*, sarif: dict[str, Any], ledger: dict[str, Any]) -> dict[str, Any]:
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
        "repo": os.environ.get("GITHUB_REPOSITORY", ""),
        "ref": os.environ.get("GITHUB_REF_NAME", ""),
        "sha": os.environ.get("GITHUB_SHA", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
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
        "sarif_error": sarif.get("_error"),
        "ledger_error": ledger.get("_error"),
    }


def _result_summary(result: dict[str, Any], rule: dict[str, Any]) -> dict[str, str]:
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
    attempts = ledger.get("attempts") or []
    scans = ledger.get("scans") or []
    selected_rules = []
    for attempt in attempts:
        if isinstance(attempt, dict):
            selected_rules.extend(attempt.get("selected_rules") or [])
    return {
        "status": ledger.get("status") or ledger.get("outcome") or "unknown",
        "message": ledger.get("message") or "",
        "attempt_count": len(attempts),
        "scan_count": len(scans),
        "selected_rule_count": len(selected_rules),
        "selected_rules": selected_rules[:12],
    }


def _render_html(*, summary: dict[str, Any], generated_at: str, page_url: str, code_scanning_url: str, run_url: str) -> str:
    by_reach = summary.get("by_reachability") or {}
    by_type = summary.get("by_type") or {}
    by_family = summary.get("by_family") or {}
    remediation = summary.get("remediation") or {}
    compliance = summary.get("compliance") or {}
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
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Reachable Go Demo - Last Scan</title>
  <style>
    :root {{ color-scheme: light dark; --bg:#0e151c; --fg:#f7fafc; --muted:#98a7b5; --line:#253342; --card:#141f29; --accent:#5fe0a3; --warn:#ffd166; }}
    body {{ margin:0; font-family:Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:var(--bg); color:var(--fg); }}
    main {{ max-width:1160px; margin:0 auto; padding:32px 20px 48px; }}
    h1 {{ margin:0 0 8px; font-size:32px; letter-spacing:0; }}
    h2 {{ margin:32px 0 12px; font-size:20px; }}
    p {{ color:var(--muted); line-height:1.5; }}
    a {{ color:var(--accent); }}
    .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; margin:24px 0; }}
    .card {{ background:var(--card); border:1px solid var(--line); border-radius:8px; padding:16px; }}
    .num {{ font-size:28px; font-weight:750; }}
    .label {{ color:var(--muted); font-size:13px; margin-top:4px; }}
    .links {{ display:flex; flex-wrap:wrap; gap:10px; margin:18px 0 4px; }}
    .links a {{ border:1px solid var(--line); border-radius:6px; padding:8px 10px; text-decoration:none; background:#101923; }}
    table {{ width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); border-radius:8px; overflow:hidden; }}
    th, td {{ padding:10px 12px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; font-size:14px; }}
    th {{ color:#dce7ee; background:#111b26; }}
    .muted {{ color:var(--muted); }}
    .pill {{ display:inline-block; border:1px solid var(--line); border-radius:999px; padding:2px 8px; font-size:12px; }}
    .reachable {{ color:var(--accent); }}
    .warning {{ color:var(--warn); }}
    code {{ word-break:break-word; }}
  </style>
</head>
<body>
  <main>
    <h1>Reachable Go Demo - Last Scan</h1>
    <p>Public, sanitized summary of the latest CI scan/remediation proof. This page lists production actionable signals only: exploitable, reachable, unknown, and defended/defendable findings. Full private prompts, agent transcripts, rules, and local databases are not published here.</p>
    <div class="links">
      <a href="{html.escape(code_scanning_url)}">GitHub code scanning alerts</a>
      <a href="{html.escape(run_url)}">GitHub Actions run</a>
      <a href="reachable.sarif">Download selected SARIF</a>
      <a href="remediation-ledger.json">Download remediation ledger</a>
      {_compliance_links(compliance)}
    </div>
    <div class="cards">
      {_card("Production actionable signals", str(summary.get("total", 0)))}
      {_card("Exploitable", str(by_reach.get("EXPLOITABLE", 0)))}
      {_card("Reachable", str(by_reach.get("REACHABLE", 0)))}
      {_card("Unknown", str(by_reach.get("UNKNOWN", 0)))}
      {_card("Defended / defendable", str(defended_count))}
      {_card("CVE", str(by_type.get("CVE", 0)))}
      {_card("CWE", str(by_type.get("CWE", 0)))}
      {_card("Secrets", str(by_type.get("SECRET", 0)))}
      {_card("Malware", str(by_type.get("MALWARE", 0)))}
      {_card("Suspicious packages", str(suspicious_count))}
      {_card("DLP / PII", str(by_family.get("DLP / PII", 0)))}
      {_card("OWASP Web Top 10", str(by_family.get("OWASP Web Top 10", 0)))}
      {_card("OWASP AI / LLM", str(by_family.get("OWASP AI / LLM", 0)))}
    </div>
    <h2>Production Actionable: Exploitable / Reachable</h2>
    <table>
      <thead><tr><th>Signal</th><th>Reachability</th><th>Risk</th><th>Families</th><th>Package</th><th>Fix</th><th>Location</th><th>Message</th></tr></thead>
      <tbody>{priority_rows}</tbody>
    </table>
    <h2>Production Actionable: Defended / Defendable</h2>
    <table>
      <thead><tr><th>Signal</th><th>Reachability</th><th>Risk</th><th>Families</th><th>Package</th><th>Fix</th><th>Location</th><th>Message</th></tr></thead>
      <tbody>{defended_rows}</tbody>
    </table>
    <h2>All Production Actionable Signals</h2>
    <table>
      <thead><tr><th>Signal</th><th>Reachability</th><th>Risk</th><th>Families</th><th>Package</th><th>Fix</th><th>Location</th><th>Message</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
    <h2>Remediation Attempt</h2>
    <p>Status: <strong>{html.escape(str(remediation.get("status") or "unknown"))}</strong>. {html.escape(str(remediation.get("message") or ""))}</p>
    <table>
      <thead><tr><th>Rule</th><th>Package</th><th>Signals</th><th>Suggested fix</th></tr></thead>
      <tbody>{rule_rows}</tbody>
    </table>
    <p class="muted">Generated at {html.escape(generated_at)} for {html.escape(str(summary.get("repo") or ""))} / {html.escape(str(summary.get("ref") or ""))}. Page URL: {html.escape(page_url)}</p>
  </main>
</body>
</html>
"""


def _card(label: str, value: str) -> str:
    return f'<div class="card"><div class="num">{html.escape(value)}</div><div class="label">{html.escape(label)}</div></div>'


def _compliance_links(compliance: dict[str, Any]) -> str:
    if not compliance.get("available"):
        return ""
    links = []
    if compliance.get("markdown"):
        links.append('<a href="compliance.md">Download compliance pack</a>')
    if compliance.get("json"):
        links.append('<a href="compliance.json">Download compliance JSON</a>')
    return "\n      ".join(links)


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
    compliance = summary.get("compliance") or {}
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
        f"- Remediation status: `{remediation.get('status', 'unknown')}`",
        f"- Compliance evidence pack: `{('available from Pages' if compliance.get('available') else 'not available')}`",
        f"- Pages summary: {page_url or 'available after Pages deployment'}",
        f"- Code scanning: {code_scanning_url}",
        f"- Actions run: {run_url}",
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
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    return f"{server}/{repo}/security/code-scanning?query=category%3Areachable" if repo else ""


def _run_url() -> str:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    return f"{server}/{repo}/actions/runs/{run_id}" if repo and run_id else ""


def _pages_url() -> str:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repo:
        return ""
    owner, name = repo.split("/", 1)
    return f"https://{owner}.github.io/{name}/"


if __name__ == "__main__":
    raise SystemExit(main())

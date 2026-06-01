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
import shutil
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"error": 0, "warning": 1, "note": 2, "none": 3}
REACHABILITY_ORDER = {"exploitable": 0, "reachable": 1, "unknown": 2}


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

    summary = _summarize(sarif=sarif, ledger=ledger)
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

    return {
        "repo": os.environ.get("GITHUB_REPOSITORY", ""),
        "ref": os.environ.get("GITHUB_REF_NAME", ""),
        "sha": os.environ.get("GITHUB_SHA", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "total": len(findings),
        "by_level": dict(Counter(item["level"] for item in findings)),
        "by_type": dict(Counter(item["type"] for item in findings)),
        "by_reachability": dict(Counter(item["reachability"] for item in findings)),
        "top_priority": top_priority,
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
    reachability = str(props.get("reachabilityState") or "unknown").upper()
    level = str(result.get("level") or "warning").lower()
    title = str(((rule.get("shortDescription") or {}).get("text")) or rule.get("name") or rule_id)
    return {
        "rule_id": rule_id,
        "type": prefix,
        "title": title,
        "message": message,
        "level": level,
        "reachability": reachability,
        "package": package,
        "fix": fix,
        "location": _location(result),
    }


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
        SEVERITY_ORDER.get(item["level"], 9),
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
    by_level = summary.get("by_level") or {}
    remediation = summary.get("remediation") or {}
    priority_rows = "\n".join(_issue_row(item) for item in summary.get("top_priority") or [])
    if not priority_rows:
        priority_rows = '<tr><td colspan="7">No exploitable or reachable findings were reported.</td></tr>'
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
    <p>Public, sanitized summary of the latest CI scan/remediation proof. Full private prompts, agent transcripts, rules, and local databases are not published here.</p>
    <div class="links">
      <a href="{html.escape(code_scanning_url)}">GitHub code scanning alerts</a>
      <a href="{html.escape(run_url)}">GitHub Actions run</a>
      <a href="reachable.sarif">Download selected SARIF</a>
      <a href="remediation-ledger.json">Download remediation ledger</a>
    </div>
    <div class="cards">
      {_card("Actionable SARIF findings", str(summary.get("total", 0)))}
      {_card("Reachable", str(by_reach.get("REACHABLE", 0)))}
      {_card("Exploitable", str(by_reach.get("EXPLOITABLE", 0)))}
      {_card("Unknown", str(by_reach.get("UNKNOWN", 0)))}
      {_card("CVE", str(by_type.get("CVE", 0)))}
      {_card("CWE", str(by_type.get("CWE", 0)))}
      {_card("Errors", str(by_level.get("error", 0)))}
      {_card("Warnings", str(by_level.get("warning", 0)))}
    </div>
    <h2>Top Exploitable / Reachable Issues</h2>
    <table>
      <thead><tr><th>Signal</th><th>Reachability</th><th>Level</th><th>Package</th><th>Fix</th><th>Location</th><th>Message</th></tr></thead>
      <tbody>{priority_rows}</tbody>
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


def _issue_row(item: dict[str, str]) -> str:
    reach_class = "reachable" if item.get("reachability") in {"REACHABLE", "EXPLOITABLE"} else ""
    level_class = "warning" if item.get("level") == "warning" else ""
    return (
        "<tr>"
        f"<td><code>{html.escape(item.get('rule_id', ''))}</code></td>"
        f"<td><span class=\"pill {reach_class}\">{html.escape(item.get('reachability', ''))}</span></td>"
        f"<td><span class=\"{level_class}\">{html.escape(item.get('level', ''))}</span></td>"
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
    remediation = summary.get("remediation") or {}
    lines = [
        "## Reachable Go Demo - Last Scan",
        "",
        f"- Findings in selected SARIF: `{summary.get('total', 0)}`",
        f"- Exploitable: `{by_reach.get('EXPLOITABLE', 0)}`",
        f"- Reachable: `{by_reach.get('REACHABLE', 0)}`",
        f"- Unknown: `{by_reach.get('UNKNOWN', 0)}`",
        f"- CVE: `{by_type.get('CVE', 0)}`",
        f"- CWE: `{by_type.get('CWE', 0)}`",
        f"- Remediation status: `{remediation.get('status', 'unknown')}`",
        f"- Pages summary: {page_url or 'available after Pages deployment'}",
        f"- Code scanning: {code_scanning_url}",
        f"- Actions run: {run_url}",
        "",
        "### Top exploitable / reachable issues",
        "",
    ]
    for item in (summary.get("top_priority") or [])[:10]:
        suffix = f" fix `{item['fix']}`" if item.get("fix") else ""
        location = f" at `{item['location']}`" if item.get("location") else ""
        lines.append(f"- `{item['rule_id']}` {item['reachability']} {item['level']}{suffix}{location}")
    if not (summary.get("top_priority") or []):
        lines.append("- No exploitable or reachable findings were reported.")
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

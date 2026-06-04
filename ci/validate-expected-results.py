#!/usr/bin/env python3
"""Validate reach-testbed-go scanner output against the golden baseline."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _counter_from_rows(rows: list[sqlite3.Row], key: str) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for row in rows:
        value = row[key]
        counts[str(value or "UNKNOWN")] += 1
    return dict(sorted(counts.items()))


def _expect(label: str, actual: Any, expected: Any, errors: list[str]) -> None:
    if actual != expected:
        errors.append(f"{label}: expected {expected!r}, got {actual!r}")


def _db_rows(db_path: Path, scan_id: int) -> list[sqlite3.Row]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return list(
            conn.execute(
                """
                SELECT id, signal_type, file_path, line_number, app_reachability,
                       prod_status, risk_level
                FROM signals
                WHERE scan_id = ?
                ORDER BY id
                """,
                (scan_id,),
            )
        )
    finally:
        conn.close()


def _attacker_counts(db_path: Path, scan_id: int) -> dict[str, int]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = list(
            conn.execute(
                """
                SELECT exploitable, COALESCE(error, '') AS error
                FROM enzo_attacker_audit
                WHERE scan_id = ?
                """,
                (scan_id,),
            )
        )
    finally:
        conn.close()

    errors = sum(1 for row in rows if row["error"])
    exploitable = sum(1 for row in rows if int(row["exploitable"] or 0) == 1)
    defended = sum(1 for row in rows if int(row["exploitable"] or 0) == 0 and not row["error"])
    return {
        "tasks": len(rows),
        "exploitable": exploitable,
        "defended": defended,
        "errors": errors,
        "skipped": 0,
    }


def _action_required(rows: list[sqlite3.Row], db_path: Path, scan_id: int) -> dict[str, Any]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        defended = {
            (row["finding_type"].lower(), row["file_path"], int(row["line_number"] or 0))
            for row in conn.execute(
                """
                SELECT finding_type, file_path, line_number
                FROM enzo_attacker_audit
                WHERE scan_id = ? AND exploitable = 0 AND COALESCE(error, '') = ''
                """,
                (scan_id,),
            )
        }
    finally:
        conn.close()

    selected = []
    for row in rows:
        state = str(row["app_reachability"] or "UNKNOWN").upper()
        prod = str(row["prod_status"] or "UNKNOWN").upper()
        if state not in {"EXPLOITABLE", "REACHABLE", "UNKNOWN"}:
            continue
        if prod == "NON_PROD":
            continue
        key = (str(row["signal_type"]).lower(), row["file_path"], int(row["line_number"] or 0))
        if key in defended:
            continue
        selected.append(row)

    by_type = Counter(str(row["signal_type"]).lower() for row in selected)
    return {"total": len(selected), "by_type": dict(sorted(by_type.items()))}


def _sarif_rows(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    sarif = _load_json(path)
    runs = sarif.get("runs") or []
    if not runs:
        return sarif, []
    return sarif, list(runs[0].get("results") or [])


def _sarif_tuple(result: dict[str, Any]) -> tuple[Any, ...]:
    loc = ((result.get("locations") or [{}])[0].get("physicalLocation") or {})
    artifact = (loc.get("artifactLocation") or {}).get("uri") or ""
    region = loc.get("region") or {}
    props = result.get("properties") or {}
    return (
        result.get("ruleId"),
        props.get("reachabilityState"),
        props.get("riskLevel"),
        props.get("prodStatus"),
        artifact,
        int(region.get("startLine") or 0),
    )


def _suffix_tuple(item: tuple[Any, ...]) -> tuple[Any, ...]:
    rule, reach, risk, prod, path, line = item
    return (rule, reach, risk, prod, str(path), int(line or 0))


def validate(args: argparse.Namespace) -> int:
    expected = _load_json(Path(args.expected))
    errors: list[str] = []

    rows = _db_rows(Path(args.db), args.scan_id)
    db_expected = expected["db"]
    _expect("db.total_signals", len(rows), db_expected["total_signals"], errors)
    _expect("db.by_type", _counter_from_rows(rows, "signal_type"), db_expected["by_type"], errors)
    _expect("db.by_reachability", _counter_from_rows(rows, "app_reachability"), db_expected["by_reachability"], errors)
    _expect("db.by_prod_status", _counter_from_rows(rows, "prod_status"), db_expected["by_prod_status"], errors)
    _expect("db.by_risk", _counter_from_rows(rows, "risk_level"), db_expected["by_risk"], errors)
    _expect("db.action_required", _action_required(rows, Path(args.db), args.scan_id), db_expected["action_required"], errors)
    _expect("db.attacker", _attacker_counts(Path(args.db), args.scan_id), db_expected["attacker"], errors)

    sarif, results = _sarif_rows(Path(args.sarif))
    sarif_expected = expected["sarif"]
    _expect("sarif.version", sarif.get("version"), "2.1.0", errors)
    _expect("sarif.total_results", len(results), sarif_expected["total_results"], errors)
    run = (sarif.get("runs") or [{}])[0]
    props = run.get("properties") or {}
    _expect("sarif.totalActionable", props.get("totalActionable"), sarif_expected["total_actionable"], errors)
    _expect(
        "sarif.totalProductionPosture",
        props.get("totalProductionPosture"),
        sarif_expected["total_production_posture"],
        errors,
    )
    _expect("sarif.byType", props.get("byType"), sarif_expected["by_type"], errors)
    _expect("sarif.byReachability", props.get("byReachability"), {k.upper(): v for k, v in sarif_expected["by_reachability"].items()}, errors)

    by_level = Counter(str(result.get("level") or "warning") for result in results)
    by_reach = Counter(str((result.get("properties") or {}).get("reachabilityState") or "unknown") for result in results)
    by_prod = Counter(str((result.get("properties") or {}).get("prodStatus") or "UNKNOWN") for result in results)
    _expect("sarif.by_level", dict(sorted(by_level.items())), sarif_expected["by_level"], errors)
    _expect("sarif.by_reachability", dict(sorted(by_reach.items())), sarif_expected["by_reachability"], errors)
    _expect("sarif.by_prod_status", dict(sorted(by_prod.items())), sarif_expected["by_prod_status"], errors)

    actual_rows = Counter()
    for result in results:
        row = _sarif_tuple(result)
        rel = str(row[4])
        for marker in ("/internal/", "/cmd/", "/config/", "/deploy/", "/testdata/"):
            if marker in rel:
                rel = rel.split(marker, 1)[1]
                rel = marker.strip("/") + "/" + rel
                break
        actual_rows[(row[0], row[1], row[2], row[3], rel, row[5])] += 1
        message = ((result.get("message") or {}).get("text") or "")
        if "ghp_" in message or "***" in message:
            errors.append(f"sarif secret hygiene: credential-shaped text in {result.get('ruleId')}")

    expected_rows = Counter(_suffix_tuple(tuple(item)) for item in sarif_expected["results"])
    if actual_rows != expected_rows:
        missing = expected_rows - actual_rows
        extra = actual_rows - expected_rows
        if missing:
            errors.append(f"sarif.results missing: {sorted(missing.elements())}")
        if extra:
            errors.append(f"sarif.results extra: {sorted(extra.elements())}")

    if errors:
        print("Reachable Go expected-results validation FAILED", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("Reachable Go expected-results validation passed")
    print(f"  DB signals: {len(rows)}")
    print(f"  SARIF compatibility export rows: {len(results)}")
    print(f"  Attack Prompt: {db_expected['attacker']['exploitable']} exploitable, {db_expected['attacker']['defended']} defended")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, help="Path to repo.db")
    parser.add_argument("--scan-id", required=True, type=int, help="Scan id to validate")
    parser.add_argument("--sarif", required=True, help="Path to SARIF file")
    parser.add_argument(
        "--expected",
        default=str(Path(__file__).resolve().parents[1] / "expected" / "baseline.json"),
        help="Path to expected baseline JSON",
    )
    return validate(parser.parse_args())


if __name__ == "__main__":
    sys.exit(main())

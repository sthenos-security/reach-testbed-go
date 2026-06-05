#!/usr/bin/env python3
"""Gate the demo on Reachable repo.db truth."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


def _load_pages_module() -> Any:
    module_path = Path(__file__).with_name("build-pages-summary.py")
    spec = importlib.util.spec_from_file_location("reachable_pages_summary", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    artifact_dir = Path(sys.argv[1] if len(sys.argv) > 1 else ".reachable/ci-artifacts")
    out_path = artifact_dir / "db-remediation-verdict.json"
    module = _load_pages_module()
    verdict = module._expected_demo_summary(artifact_dir=artifact_dir)
    blocking_rows = [
        row
        for row in verdict.get("rows", [])
        if row.get("status") in {"still_present", "baseline_missing"}
    ]
    payload = {
        "source": "repo.db",
        "clean": bool(verdict.get("clean")),
        "headline": verdict.get("headline"),
        "expected_total": verdict.get("expected_total", 0),
        "baseline_found": verdict.get("baseline_found", 0),
        "baseline_missing": verdict.get("baseline_missing", 0),
        "fixed": verdict.get("fixed", 0),
        "still_present": verdict.get("still_present", 0),
        "after_blocking_total": verdict.get("after_total", 0),
        "baseline_scan": verdict.get("baseline", {}),
        "after_scan": verdict.get("after", {}),
        "blocking_rows": [
            {
                "rule_id": row.get("rule_id"),
                "location": row.get("location"),
                "status": row.get("status"),
                "status_label": row.get("status_label"),
                "risk": row.get("actual_risk") or row.get("expected_risk"),
                "reachability": row.get("actual_reachability") or row.get("expected_reachability"),
            }
            for row in blocking_rows
        ],
    }
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Reachable DB remediation verdict: {payload['headline']}")
    print(
        "Reachable DB proof: "
        f"expected={payload['expected_total']} "
        f"baseline_found={payload['baseline_found']} "
        f"fixed={payload['fixed']} "
        f"still_present={payload['still_present']} "
        f"after_blocking={payload['after_blocking_total']}"
    )
    print(f"Reachable DB baseline scan: {payload['baseline_scan'].get('db_scan_id')} @ {payload['baseline_scan'].get('commit_short')}")
    print(f"Reachable DB proof scan: {payload['after_scan'].get('db_scan_id')} @ {payload['after_scan'].get('commit_short')}")
    if payload["clean"]:
        return 0
    for row in payload["blocking_rows"]:
        print(
            "DB proof blocker: "
            f"{row.get('rule_id')} {row.get('status_label')} at {row.get('location')}",
            file=sys.stderr,
        )
    return 3


if __name__ == "__main__":
    raise SystemExit(main())

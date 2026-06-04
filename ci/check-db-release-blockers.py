#!/usr/bin/env python3
"""Gate a single Reachable scan from repo.db release-blocker truth."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
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


def _scan_context(scan_path: Path) -> dict[str, Any]:
    scan_dir = scan_path.resolve()
    db_path = scan_dir.parents[1] / "repo.db"
    if not db_path.exists():
        raise FileNotFoundError(f"repo.db not found for scan path: {scan_dir}")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT id, branch, commit_short, commit_hash, scan_dir, timestamp, status
              FROM scans
             ORDER BY id DESC
            """,
        ).fetchall()
    finally:
        conn.close()
    row = None
    for candidate in rows:
        try:
            if Path(str(candidate["scan_dir"])).resolve() == scan_dir:
                row = candidate
                break
        except (OSError, RuntimeError):
            if str(candidate["scan_dir"]) == str(scan_dir):
                row = candidate
                break
    if row is None:
        raise RuntimeError(f"scan directory was not found in repo.db scans table: {scan_dir}")
    return {
        "db_path": str(db_path),
        "scan_id": int(row["id"]),
        "branch": row["branch"],
        "commit_short": row["commit_short"],
        "commit_hash": row["commit_hash"],
        "timestamp": row["timestamp"],
        "status": row["status"],
    }


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: check-db-release-blockers.py SCAN_PATH [OUT_JSON]", file=sys.stderr)
        return 2
    scan_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    module = _load_pages_module()
    ctx = _scan_context(scan_path)
    blockers = int(module._db_actionable_count(ctx))
    payload = {
        "source": "repo.db",
        "clean": blockers == 0,
        "release_blockers": blockers,
        "scan": {
            "db_path": ctx["db_path"],
            "db_scan_id": ctx["scan_id"],
            "branch": ctx.get("branch"),
            "commit_short": ctx.get("commit_short"),
            "commit_hash": ctx.get("commit_hash"),
            "timestamp": ctx.get("timestamp"),
            "status": ctx.get("status"),
        },
    }
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        "Reachable DB release-blocker gate: "
        f"scan={ctx['scan_id']} branch={ctx.get('branch')} "
        f"commit={ctx.get('commit_short')} release_blockers={blockers}"
    )
    if blockers:
        print(
            "Reachable DB release-blocker gate failed: "
            f"{blockers} release-blocking finding(s) remain.",
            file=sys.stderr,
        )
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

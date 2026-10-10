"""Run a SQLite demo with synthetic data on Windows, macOS or Linux."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def command(*args: str, expected: int = 0) -> None:
    print("\n> masker " + " ".join(args), flush=True)
    result = subprocess.run([sys.executable, "-m", "masker", *args], cwd=ROOT, check=False)
    if result.returncode != expected:
        raise RuntimeError(f"Expected exit {expected}, got {result.returncode}")


def snapshot(path: Path) -> dict[str, list[tuple[object, ...]]]:
    conn = sqlite3.connect(path)
    try:
        names = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        ]
        return {
            name: sorted(conn.execute(f'SELECT * FROM "{name}"').fetchall(), key=repr)
            for name in names
        }
    finally:
        conn.close()


def main() -> None:
    os.environ["MASKER_SECRET_KEY"] = "synthetic-demo-only-key-0123456789abcdef"
    os.environ["PYTHONUTF8"] = "1"
    with tempfile.TemporaryDirectory(prefix="masker-demo-") as directory:
        work = Path(directory)
        source, target, again, leaky = [
            work / name
            for name in ("source.sqlite", "target.sqlite", "again.sqlite", "leaky.sqlite")
        ]
        subprocess.run(
            [sys.executable, str(ROOT / "examples/make_demo_db.py"), str(source)], check=True
        )
        source_before = snapshot(source)
        source_url, target_url = f"sqlite:///{source}", f"sqlite:///{target}"
        rules = str(ROOT / "examples/masker.yaml")
        command("init", "--source", source_url, "--output", str(work / "generated.yaml"))
        command("scan", "--source", source_url, "--strict", expected=1)
        command("scan", "--source", source_url, "--rules", rules, "--strict")
        command("validate", "--source", source_url, "--rules", rules)
        common = ("--source", source_url, "--target", target_url, "--rules", rules)
        command("run", *common, "--dry-run", "--sample-rows", "1")
        assert not target.exists(), "Dry-run wrote to target"
        command("run", *common, "--yes", "--stats-file", str(work / "stats.json"))
        command("verify", *common)
        command(
            "report",
            "--input",
            str(work / "stats.json"),
            "--format",
            "json",
            "--output",
            str(work / "report.json"),
        )
        json.loads((work / "report.json").read_text(encoding="utf-8"))
        command(
            "run",
            "--source",
            source_url,
            "--target",
            f"sqlite:///{again}",
            "--rules",
            rules,
            "--batch-size",
            "37",
            "--yes",
            "--stats-file",
            str(work / "again.json"),
        )
        assert snapshot(target) == snapshot(again), "Determinism failed"
        assert snapshot(source) == source_before, "Source was modified"
        conn = sqlite3.connect(target)
        try:
            assert not list(conn.execute("PRAGMA foreign_key_check")), "Foreign keys broke"
        finally:
            conn.close()
        reduced = yaml.safe_load(Path(rules).read_text(encoding="utf-8"))
        del reduced["tables"]["customers"]["columns"]["email"]
        leaky_rules = work / "leaky.yaml"
        leaky_rules.write_text(yaml.safe_dump(reduced), encoding="utf-8")
        command(
            "run",
            "--source",
            source_url,
            "--target",
            f"sqlite:///{leaky}",
            "--rules",
            str(leaky_rules),
            "--yes",
            "--stats-file",
            str(work / "leaky.json"),
        )
        command(
            "verify",
            "--source",
            source_url,
            "--target",
            f"sqlite:///{leaky}",
            "--rules",
            str(leaky_rules),
            expected=1,
        )
        print(
            "\nPASS: deterministic rows, unchanged source, valid FKs, "
            "dry-run, report JSON and leak detection."
        )


if __name__ == "__main__":
    main()

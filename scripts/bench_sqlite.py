#!/usr/bin/env python3
"""Generate a synthetic database and measure how fast Masker masks it.

This is the script behind the numbers in the README's *Performance* section.
It is deliberately plain SQLite with no tuning, because that is the floor: a
networked PostgreSQL or MySQL server adds latency per batch, so treat these
figures as a best case for the transformation work itself, not a promise.

Usage:
    python scripts/bench_sqlite.py                # 100k customers + 100k orders
    python scripts/bench_sqlite.py --rows 250000 --batch-size 20000
    python scripts/bench_sqlite.py --workdir /tmp/bench --keep

Nothing outside --workdir (default: a temporary directory) is touched.
"""

from __future__ import annotations

import argparse
import contextlib
import platform
import random
import sqlite3
import sys
import time
from pathlib import Path

# Allow running straight from a source checkout without installing.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from masker.config import load_rules_from_text
from masker.engine import MaskingEngine, RunOptions
from masker.keys import SecretKey

RULES = """
version: 1
tables:
  customers:
    columns:
      id:             {transformer: hash}
      email:          {transformer: email}
      full_name:      {transformer: fake, params: {provider: name}}
      phone:          {transformer: partial_mask, params: {keep_last: 4}}
      ssn:            {transformer: hash, params: {length: 11}}
      credit_card:    {transformer: partial_mask, params: {keep_last: 4}}
      date_of_birth:  {transformer: date_shift, params: {min_days: -30, max_days: 30}}
      lifetime_value: {transformer: number_noise, params: {percent: 10, round_to: 2}}
      street_address: {transformer: fake, params: {provider: street_address}}
      notes:          {transformer: redact}
  orders:
    columns:
      id:          {transformer: hash}
      customer_id: {transformer: hash}
      total:       {transformer: number_noise, params: {percent: 5, round_to: 2}}
      note:        {transformer: keep}
"""

KEY = "benchmark-only-key-not-a-secret-0123456789"


def build_database(path: Path, rows: int, seed: int = 1234) -> dict[str, int]:
    """Create a two-table schema with foreign keys and unique columns."""
    rng = random.Random(seed)
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE customers (
                id             INTEGER PRIMARY KEY,
                email          VARCHAR(120) NOT NULL UNIQUE,
                full_name      VARCHAR(80) NOT NULL,
                phone          VARCHAR(24),
                ssn            VARCHAR(11) UNIQUE,
                credit_card    VARCHAR(19),
                date_of_birth  DATE,
                lifetime_value NUMERIC(12, 2),
                street_address VARCHAR(120),
                notes          TEXT
            );
            CREATE TABLE orders (
                id          INTEGER PRIMARY KEY,
                customer_id INTEGER NOT NULL REFERENCES customers(id),
                total       NUMERIC(10, 2) NOT NULL,
                note        TEXT
            );
            """
        )
        names = ("Ada", "Grace", "Alan", "Edsger", "Barbara", "Donald", "Tony", "Radia")
        surnames = ("Lovelace", "Hopper", "Turing", "Dijkstra", "Liskov", "Knuth", "Hoare")
        customers = [
            (
                index,
                f"customer{index}@corp.example",
                f"{rng.choice(names)} {rng.choice(surnames)}",
                f"+1 (555) {rng.randint(2000000, 9999999)}",
                # Derived from the index, not random: random 11-digit SSNs
                # collide well before 100k rows.
                f"{100 + index // 10000}-{(index % 10000) // 100:02d}-{index % 100:02d}",
                f"411111{index:010d}"[:16],
                f"19{rng.randint(40, 99)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}",
                round(rng.uniform(10, 25000), 2),
                f"{rng.randint(1, 999)} {rng.choice(names)} Street",
                "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod.",
            )
            for index in range(1, rows + 1)
        ]
        conn.executemany("INSERT INTO customers VALUES (?,?,?,?,?,?,?,?,?,?)", customers)
        orders = [
            (
                index,
                ((index - 1) % rows) + 1,
                round(rng.uniform(1, 900), 2),
                "please gift wrap" if index % 3 == 0 else None,
            )
            for index in range(1, rows + 1)
        ]
        conn.executemany("INSERT INTO orders VALUES (?,?,?,?)", orders)
        conn.commit()
        return {"customers": rows, "orders": rows}
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=100_000, help="Rows per table.")
    parser.add_argument("--batch-size", type=int, default=5000)
    parser.add_argument("--workdir", type=Path, default=None)
    parser.add_argument(
        "--keep", action="store_true", help="Leave the databases on disk to inspect."
    )
    args = parser.parse_args()

    workdir = args.workdir or Path(__import__("tempfile").mkdtemp(prefix="masker-bench-"))
    workdir.mkdir(parents=True, exist_ok=True)
    source = workdir / "source.sqlite"
    target = workdir / "masked.sqlite"

    print(f"host      : {platform.platform()}")
    print(f"python    : {platform.python_version()} on {platform.machine()}")
    print(f"cpu       : {platform.processor() or 'unknown'}")
    print(f"rows      : {args.rows:,} per table (2 tables)")
    print(f"batch size: {args.batch_size:,}")

    started = time.perf_counter()
    counts = build_database(source, args.rows)
    generated = time.perf_counter() - started
    print(f"generate  : {generated:.1f}s ({sum(counts.values()):,} rows)")

    rules = load_rules_from_text(RULES)
    key = SecretKey.from_text(KEY, origin="benchmark")
    engine = MaskingEngine(
        source_url=f"sqlite:///{source}",
        target_url=f"sqlite:///{target}",
        rules=rules,
        key=key,
        options=RunOptions(batch_size=args.batch_size),
    )
    started = time.perf_counter()
    result = engine.run()
    elapsed = time.perf_counter() - started

    total_rows = result.rows_written
    masked_columns = result.masked_column_count
    print(
        f"mask      : {elapsed:.2f}s for {total_rows:,} rows ({total_rows / elapsed:,.0f} rows/s)"
    )
    print(
        f"            {masked_columns} masked column(s), "
        f"{sum(table.unique_retries for table in result.tables)} unique retries"
    )
    for table in result.tables:
        print(
            f"  {table.table:<12} {table.rows_written:>9,} rows  "
            f"{table.duration_s:>6.2f}s  {len(table.masked)} masked"
        )

    if not args.keep:
        source.unlink(missing_ok=True)
        target.unlink(missing_ok=True)
        with contextlib.suppress(OSError):
            workdir.rmdir()
    else:
        print(f"kept      : {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

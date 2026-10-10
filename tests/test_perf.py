"""Performance smoke test.

Opt-in: it generates 100k rows, so it is marked ``perf`` and skipped unless you
ask for it (``pytest -m perf``) or set ``MASKER_RUN_PERF=1``. The real numbers
quoted in the README come from ``scripts/bench_sqlite.py``.
"""

from __future__ import annotations

import os
import random
import sqlite3
import time
from pathlib import Path

import pytest

ROWS = int(os.environ.get("MASKER_PERF_ROWS", "100000"))

pytestmark = [
    pytest.mark.perf,
    pytest.mark.skipif(
        os.environ.get("MASKER_RUN_PERF") != "1",
        reason="set MASKER_RUN_PERF=1 to run the performance test",
    ),
]

RULES = """
version: 1
settings:
  batch_size: 5000
tables:
  customers:
    columns:
      id:             {transformer: hash}
      email:          {transformer: email}
      full_name:      {transformer: fake, params: {provider: name}}
      phone:          {transformer: partial_mask, params: {keep_last: 4}}
      ssn:            {transformer: hash, params: {length: 11}}
      date_of_birth:  {transformer: date_shift, params: {min_days: -30, max_days: 30}}
      lifetime_value: {transformer: number_noise, params: {percent: 10, round_to: 2}}
      notes:          {transformer: redact}
  orders:
    columns:
      id:          {transformer: hash}
      customer_id: {transformer: hash}
      total:       {transformer: number_noise, params: {percent: 5, round_to: 2}}
"""


@pytest.fixture(scope="module")
def big_db(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("perf") / "big.sqlite"
    conn = sqlite3.connect(path)
    rng = random.Random(1234)
    try:
        conn.execute(
            """
            CREATE TABLE customers (
                id INTEGER PRIMARY KEY,
                email VARCHAR(120) NOT NULL UNIQUE,
                full_name VARCHAR(80) NOT NULL,
                phone VARCHAR(24),
                ssn VARCHAR(11) UNIQUE,
                date_of_birth DATE,
                lifetime_value NUMERIC(12, 2),
                notes TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE orders (
                id INTEGER PRIMARY KEY,
                customer_id INTEGER NOT NULL REFERENCES customers(id),
                total NUMERIC(10, 2) NOT NULL
            )
            """
        )
        customers = [
            (
                index,
                f"customer{index}@corp.example",
                f"Customer {index}",
                f"+1 (555) {rng.randint(2000000, 9999999)}",
                # Derived from the index: random 11-digit SSNs collide long
                # before 100k rows, and the column is UNIQUE.
                f"{100 + index // 10000}-{(index % 10000) // 100:02d}-{index % 100:02d}",
                f"19{rng.randint(40, 99)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}",
                round(rng.uniform(10, 10000), 2),
                "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
            )
            for index in range(1, ROWS + 1)
        ]
        conn.executemany("INSERT INTO customers VALUES (?,?,?,?,?,?,?,?)", customers)
        orders = [
            (
                index,
                ((index - 1) % ROWS) + 1,
                round(rng.uniform(1, 500), 2),
            )
            for index in range(1, ROWS + 1)
        ]
        conn.executemany("INSERT INTO orders VALUES (?,?,?)", orders)
        conn.commit()
    finally:
        conn.close()
    return path


def test_masks_100k_rows(big_db: Path, tmp_path: Path) -> None:
    from masker.config import load_rules_from_text
    from masker.engine import MaskingEngine
    from masker.keys import SecretKey

    target = tmp_path / "masked.sqlite"
    rules = load_rules_from_text(RULES)
    key = SecretKey.from_text("perf-test-key-0123456789abcdef", origin="perf")

    started = time.perf_counter()
    result = MaskingEngine(
        source_url=f"sqlite:///{big_db}",
        target_url=f"sqlite:///{target}",
        rules=rules,
        key=key,
    ).run()
    elapsed = time.perf_counter() - started

    assert result.rows_written == ROWS * 2
    # A deliberately generous ceiling: this guards against a pathological
    # slowdown, not against benchmark noise. See the README for real numbers.
    assert elapsed < 300, f"{ROWS * 2} rows took {elapsed:.1f}s"

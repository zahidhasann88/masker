"""Full CLI walkthrough on SQLite: init -> scan -> validate -> run -> verify.

This is the path a new user takes, exercised end to end against a schema with
foreign keys, a self-reference, a cycle and unique columns.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from masker.cli import app
from masker.config import load_rules

runner = CliRunner()


def invoke(*args: str) -> object:
    return runner.invoke(app, list(args))


@pytest.fixture
def shop_db(tmp_path: Path) -> Path:
    """A small shop schema, deliberately holding realistic-looking PII."""
    path = tmp_path / "shop.sqlite"
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE customers (
                id            INTEGER PRIMARY KEY,
                email         VARCHAR(120) NOT NULL UNIQUE,
                full_name     VARCHAR(80) NOT NULL,
                phone         VARCHAR(24),
                ssn           VARCHAR(11) UNIQUE,
                credit_card   VARCHAR(19),
                date_of_birth DATE,
                street_address VARCHAR(120),
                city          VARCHAR(60),
                ip_address    VARCHAR(45),
                password_hash VARCHAR(64),
                notes         TEXT,
                lifetime_value NUMERIC(12, 2),
                created_at    TIMESTAMP NOT NULL
            );
            CREATE TABLE support_agents (
                id         INTEGER PRIMARY KEY,
                manager_id INTEGER REFERENCES support_agents(id),
                email      VARCHAR(120) NOT NULL UNIQUE
            );
            CREATE TABLE orders (
                id          INTEGER PRIMARY KEY,
                customer_id INTEGER NOT NULL REFERENCES customers(id),
                agent_id    INTEGER REFERENCES support_agents(id),
                total       NUMERIC(10, 2) NOT NULL,
                ordered_at  TIMESTAMP NOT NULL
            );
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY,
                detail TEXT
            );
            """
        )
        for index in range(1, 26):
            conn.execute(
                "INSERT INTO customers VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    index,
                    f"customer{index}@shop.example",
                    f"Customer {index}",
                    f"+1 (555) 01{index:02d}",
                    f"{100 + index}-45-{6789 + index}",
                    "4111111111111111",
                    f"19{60 + index % 40}-0{(index % 9) + 1}-1{(index % 8) + 1}",
                    f"{index} Main Street",
                    "Springfield",
                    f"192.168.1.{index}",
                    "5f4dcc3b5aa765d61d8327deb882cf99",
                    "Prefers gift wrapping; called twice about the delivery.",
                    round(100.5 * index, 2),
                    "2024-01-01 09:00:00",
                ),
            )
        for agent in range(1, 5):
            conn.execute(
                "INSERT INTO support_agents VALUES (?,?,?)",
                (agent, None if agent == 1 else agent - 1, f"agent{agent}@shop.example"),
            )
        for order in range(1, 61):
            conn.execute(
                "INSERT INTO orders VALUES (?,?,?,?,?)",
                (
                    order,
                    ((order - 1) % 25) + 1,
                    ((order - 1) % 4) + 1,
                    10.0 * order,
                    "2024-02-01 10:00:00",
                ),
            )
        conn.execute("INSERT INTO audit_log VALUES (1, 'seeded')")
        conn.commit()
    finally:
        conn.close()
    return path


@pytest.fixture
def shop_url(shop_db: Path) -> str:
    return f"sqlite:///{shop_db}"


def test_full_walkthrough(shop_url: str, tmp_path: Path, with_key: Callable[[str], None]) -> None:
    with_key()
    rules_path = tmp_path / "masker.yaml"
    target_path = tmp_path / "masked.sqlite"
    target_url = f"sqlite:///{target_path}"

    # 1. init -- the starter file covers every column.
    init = invoke("init", "--source", shop_url, "--output", str(rules_path))
    assert init.exit_code == 0, init.output
    text = rules_path.read_text(encoding="utf-8")
    for column in ("email", "full_name", "ssn", "credit_card", "date_of_birth", "password_hash"):
        assert column in text
    assert "SUGGESTED" in text

    # 2. scan -- before any rules exist, the PII columns are flagged.
    strict = invoke("scan", "--source", shop_url, "--strict")
    assert strict.exit_code == 1
    assert "customers.email" in strict.output

    # 3. validate -- the generated file parses and the suggestions build.
    validation = invoke("validate", "--rules", str(rules_path), "--source", shop_url)
    assert validation.exit_code == 0, validation.output

    # 4. run -- dry run first, then the real thing.
    dry = invoke(
        "run",
        "--source",
        shop_url,
        "--target",
        target_url,
        "--rules",
        str(rules_path),
        "--dry-run",
    )
    assert dry.exit_code == 0, dry.output
    assert not target_path.exists()
    assert "customer1@shop.example" not in dry.output

    stats_path = tmp_path / "run.json"
    run = invoke(
        "run",
        "--source",
        shop_url,
        "--target",
        target_url,
        "--rules",
        str(rules_path),
        "--yes",
        "--stats-file",
        str(stats_path),
    )
    assert run.exit_code == 0, run.output
    assert stats_path.is_file()

    # 5. verify -- no leaks, no orphans, no unmasked PII.
    check = invoke(
        "verify", "--source", shop_url, "--target", target_url, "--rules", str(rules_path)
    )
    assert check.exit_code == 0, check.output

    # 6. report -- both formats.
    markdown = invoke("report", "--input", str(stats_path))
    assert markdown.exit_code == 0
    assert "customers" in markdown.output
    as_json = invoke("report", "--input", str(stats_path), "--format", "json")
    assert as_json.exit_code == 0

    # 7. The copy is intact and de-identified.
    source = sqlite3.connect(shop_url.replace("sqlite:///", ""))
    target = sqlite3.connect(target_path)
    try:
        assert (
            source.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
            == target.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
            == 60
        )
        originals = {row[0] for row in source.execute("SELECT email FROM customers")}
        masked = {row[0] for row in target.execute("SELECT email FROM customers")}
        assert not originals & masked
        assert len(masked) == len(originals)  # still unique

        # passwords never survive
        assert (
            target.execute(
                "SELECT COUNT(*) FROM customers WHERE "
                "password_hash = '5f4dcc3b5aa765d61d8327deb882cf99'"
            ).fetchone()[0]
            == 0
        )

        # foreign keys still resolve
        assert (
            target.execute(
                "SELECT COUNT(*) FROM orders o LEFT JOIN customers c ON o.customer_id = c.id "
                "WHERE c.id IS NULL"
            ).fetchone()[0]
            == 0
        )
        assert (
            target.execute(
                "SELECT COUNT(*) FROM support_agents a LEFT JOIN support_agents m "
                "ON a.manager_id = m.id WHERE a.manager_id IS NOT NULL AND m.id IS NULL"
            ).fetchone()[0]
            == 0
        )

        # the source was not touched
        assert (
            source.execute(
                "SELECT COUNT(*) FROM customers WHERE email = 'customer1@shop.example'"
            ).fetchone()[0]
            == 1
        )
    finally:
        source.close()
        target.close()


def test_determinism_and_reproducibility(
    shop_url: str, tmp_path: Path, with_key: Callable[[str], None]
) -> None:
    with_key()
    rules_path = tmp_path / "masker.yaml"
    invoke("init", "--source", shop_url, "--output", str(rules_path))

    first, second = tmp_path / "a.sqlite", tmp_path / "b.sqlite"
    for path in (first, second):
        result = invoke(
            "run",
            "--source",
            shop_url,
            "--target",
            f"sqlite:///{path}",
            "--rules",
            str(rules_path),
            "--yes",
        )
        assert result.exit_code == 0, result.output

    def snapshot(path: Path) -> list[tuple[object, ...]]:
        conn = sqlite3.connect(path)
        try:
            return sorted(str(row) for row in conn.execute("SELECT * FROM customers ORDER BY id"))
        finally:
            conn.close()

    assert snapshot(first) == snapshot(second)


def test_deleting_a_rule_is_caught_by_verify(
    shop_url: str, tmp_path: Path, with_key: Callable[[str], None]
) -> None:
    with_key()
    rules_path = tmp_path / "masker.yaml"
    invoke("init", "--source", shop_url, "--output", str(rules_path))
    target_path = tmp_path / "masked.sqlite"
    run = invoke(
        "run",
        "--source",
        shop_url,
        "--target",
        f"sqlite:///{target_path}",
        "--rules",
        str(rules_path),
        "--yes",
    )
    assert run.exit_code == 0, run.output

    # Drop the email rule: verify must fail rather than declare success.
    rules = load_rules(rules_path)
    del rules.tables["customers"].columns["email"]
    reduced = tmp_path / "reduced.yaml"
    reduced.write_text(
        yaml.safe_dump(rules.model_dump(exclude_none=True), sort_keys=False), encoding="utf-8"
    )
    assert (
        "email"
        not in yaml.safe_load(reduced.read_text(encoding="utf-8"))["tables"]["customers"]["columns"]
    )
    check = invoke(
        "verify",
        "--source",
        shop_url,
        "--target",
        f"sqlite:///{target_path}",
        "--rules",
        str(reduced),
    )
    assert check.exit_code == 1, check.output
    assert "email" in check.output


def test_skipped_tables_are_left_out(
    shop_url: str, tmp_path: Path, with_key: Callable[[str], None]
) -> None:
    with_key()
    rules_path = tmp_path / "masker.yaml"
    invoke("init", "--source", shop_url, "--output", str(rules_path))
    text = rules_path.read_text(encoding="utf-8").replace(
        "  audit_log:\n    action: copy", "  audit_log:\n    action: skip"
    )
    if "action: skip" not in text:
        text = text.replace("  audit_log:\n", "  audit_log:\n    action: skip\n", 1)
    rules_path.write_text(text, encoding="utf-8")

    target_path = tmp_path / "masked.sqlite"
    run = invoke(
        "run",
        "--source",
        shop_url,
        "--target",
        f"sqlite:///{target_path}",
        "--rules",
        str(rules_path),
        "--yes",
    )
    assert run.exit_code == 0, run.output
    conn = sqlite3.connect(target_path)
    try:
        names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master")}
    finally:
        conn.close()
    assert "audit_log" not in names
    assert "customers" in names

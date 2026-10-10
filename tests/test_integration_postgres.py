"""Integration tests against a real PostgreSQL server.

These are skipped unless ``MASKER_TEST_POSTGRES_URL`` points at a reachable
database. In CI the Linux job provides a Postgres service container and sets
that variable; locally you can point it at a disposable database:

    export MASKER_TEST_POSTGRES_URL="postgresql+psycopg://postgres@localhost:5432/masker_test"
    pytest tests/test_integration_postgres.py

The database is created from scratch and dropped afterwards, so never point it
at anything you care about.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

URL = os.environ.get("MASKER_TEST_POSTGRES_URL", "")

pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(not URL, reason="set MASKER_TEST_POSTGRES_URL to run the PostgreSQL tests"),
]

SCHEMA = """
CREATE TABLE customers (
    id            SERIAL PRIMARY KEY,
    email         VARCHAR(120) NOT NULL UNIQUE,
    full_name     VARCHAR(80) NOT NULL,
    phone         VARCHAR(24),
    ssn           VARCHAR(11) UNIQUE,
    date_of_birth DATE,
    lifetime_value NUMERIC(12, 2),
    created_at    TIMESTAMP NOT NULL
);
CREATE TABLE orders (
    id          SERIAL PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    total       NUMERIC(10, 2) NOT NULL
);
"""

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
      date_of_birth:  {transformer: date_shift, params: {min_days: -30, max_days: 30}}
      lifetime_value: {transformer: number_noise, params: {percent: 10, round_to: 2}}
  orders:
    columns:
      id:          {transformer: hash}
      customer_id: {transformer: hash}
      total:       {transformer: number_noise, params: {percent: 5, round_to: 2}}
"""


@pytest.fixture(scope="module")
def postgres_url() -> str:
    return URL


@pytest.fixture(scope="module")
def target_url() -> str:
    """A sibling database in the same server, used as the masked copy."""
    from sqlalchemy.engine import make_url

    parsed = make_url(URL)
    name = (parsed.database or "postgres") + "_masked"
    return parsed.set(database=name).render_as_string(hide_password=False)


@pytest.fixture(scope="module")
def prepared(postgres_url: str, target_url: str) -> Iterator[str]:
    """Seed the source database and make sure the target does not exist."""
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url

    parsed = make_url(postgres_url)
    server = parsed.set(database="postgres")
    admin = create_engine(server, isolation_level="AUTOCOMMIT")
    name = parsed.database or "postgres"
    if name in {"postgres", "template0", "template1"}:
        pytest.fail(
            "Use a disposable PostgreSQL database such as masker_test, not an admin database"
        )
    masked_name = name + "_masked"
    with admin.connect() as conn:
        for database in (name, masked_name):
            conn.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :name AND pid <> pg_backend_pid()"
                ),
                {"name": database},
            )
            conn.execute(text(f'DROP DATABASE IF EXISTS "{database}"'))
        conn.execute(text(f'CREATE DATABASE "{name}"'))
        conn.execute(text(f'CREATE DATABASE "{masked_name}"'))
    admin.dispose()

    source = create_engine(postgres_url)
    with source.begin() as conn:
        for statement in SCHEMA.split(";"):
            if statement.strip():
                conn.execute(text(statement))
        for index in range(1, 201):
            conn.execute(
                text(
                    "INSERT INTO customers (email, full_name, phone, ssn, date_of_birth, "
                    "lifetime_value, created_at) VALUES "
                    "(:email, :name, :phone, :ssn, :dob, :value, :created)"
                ),
                {
                    "email": f"customer{index}@corp.example",
                    "name": f"Customer {index}",
                    "phone": f"+1 (555) 01{index:02d}",
                    "ssn": f"{100 + index}-45-{6789 + index}",
                    "dob": f"19{60 + index % 40}-0{(index % 9) + 1}-1{(index % 8) + 1}",
                    "value": round(100.5 * index, 2),
                    "created": "2024-01-01 09:00:00",
                },
            )
        for order in range(1, 501):
            conn.execute(
                text("INSERT INTO orders (customer_id, total) VALUES (:customer, :total)"),
                {"customer": ((order - 1) % 200) + 1, "total": 10.0 * order},
            )
    source.dispose()
    # The databases are left in place for inspection; CI discards the container.
    return postgres_url


def test_postgres_round_trip(prepared: str, target_url: str, tmp_path: Path, with_key) -> None:
    from sqlalchemy import create_engine, text

    from masker.config import load_rules_from_text
    from masker.engine import MaskingEngine
    from masker.keys import SecretKey
    from masker.verify import verify

    with_key()
    rules = load_rules_from_text(RULES)
    key = SecretKey.from_text(os.environ["MASKER_SECRET_KEY"], origin="test")

    result = MaskingEngine(source_url=prepared, target_url=target_url, rules=rules, key=key).run()
    assert result.rows_written == 700

    engine = create_engine(target_url)
    try:
        with engine.connect() as conn:
            orphans = conn.execute(
                text(
                    "SELECT COUNT(*) FROM orders o LEFT JOIN customers c "
                    "ON o.customer_id = c.id WHERE c.id IS NULL"
                )
            ).scalar_one()
            emails = [row[0] for row in conn.execute(text("SELECT email FROM customers"))]
        assert orphans == 0
        assert len(set(emails)) == len(emails)
        assert not any(email.endswith("@corp.example") for email in emails)
    finally:
        engine.dispose()

    check = verify(source_url=prepared, target_url=target_url, rules=rules, key=key)
    assert check.leaks == ()
    assert check.broken_fks == ()


def test_postgres_source_is_read_only(prepared: str) -> None:
    """The source connection must reject writes."""
    from sqlalchemy import text as sa_text
    from sqlalchemy.exc import DBAPIError

    from masker.connect import source_engine

    with (
        source_engine(prepared) as engine,
        engine.connect() as conn,
        pytest.raises(DBAPIError, match="read-only transaction"),
    ):
        conn.execute(sa_text("DELETE FROM customers"))


def test_postgres_refuses_the_same_database(prepared: str, tmp_path: Path, with_key) -> None:
    from masker.config import load_rules_from_text
    from masker.engine import MaskingEngine
    from masker.errors import SafetyError
    from masker.keys import SecretKey

    with_key()
    rules = load_rules_from_text(RULES)
    key = SecretKey.from_text(os.environ["MASKER_SECRET_KEY"], origin="test")
    with pytest.raises(SafetyError, match="same database"):
        MaskingEngine(source_url=prepared, target_url=prepared, rules=rules, key=key).run()

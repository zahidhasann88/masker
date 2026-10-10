"""Integration tests against a real MySQL/MariaDB server.

Skipped unless ``MASKER_TEST_MYSQL_URL`` points at a reachable server. In CI
the Linux job provides a MySQL service container and sets that variable:

    export MASKER_TEST_MYSQL_URL="mysql+pymysql://root@127.0.0.1:3306/masker_test"
    pytest tests/test_integration_mysql.py

The databases are dropped and recreated, so never point this at anything you
care about.
"""

from __future__ import annotations

import os

import pytest

URL = os.environ.get("MASKER_TEST_MYSQL_URL", "")

pytestmark = [
    pytest.mark.mysql,
    pytest.mark.skipif(not URL, reason="set MASKER_TEST_MYSQL_URL to run the MySQL tests"),
]

SCHEMA = """
CREATE TABLE customers (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    email          VARCHAR(120) NOT NULL UNIQUE,
    full_name      VARCHAR(80) NOT NULL,
    phone          VARCHAR(24),
    ssn            VARCHAR(11) UNIQUE,
    date_of_birth  DATE,
    lifetime_value DECIMAL(12, 2),
    created_at     DATETIME NOT NULL
);
CREATE TABLE orders (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    customer_id INT NOT NULL,
    total       DECIMAL(10, 2) NOT NULL,
    CONSTRAINT fk_orders_customer FOREIGN KEY (customer_id) REFERENCES customers(id)
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
def mysql_url() -> str:
    return URL


@pytest.fixture(scope="module")
def target_url() -> str:
    from sqlalchemy.engine import make_url

    parsed = make_url(URL)
    return parsed.set(database=f"{parsed.database or 'masker_test'}_masked").render_as_string(
        hide_password=False
    )


@pytest.fixture(scope="module")
def prepared(mysql_url: str, target_url: str) -> str:
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url

    parsed = make_url(mysql_url)
    name = parsed.database or "masker_test"
    if name in {"mysql", "sys", "information_schema", "performance_schema"}:
        pytest.fail("Use a disposable MySQL database such as masker_test")
    masked = f"{name}_masked"
    admin = create_engine(parsed.set(database=None), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        for database in (masked, name):
            conn.execute(text(f"DROP DATABASE IF EXISTS `{database}`"))
            conn.execute(text(f"CREATE DATABASE `{database}`"))
    admin.dispose()

    source = create_engine(mysql_url)
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
    return mysql_url


def test_mysql_round_trip(prepared: str, target_url: str, with_key) -> None:
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


def test_mysql_source_is_read_only(prepared: str) -> None:
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError

    from masker.connect import source_engine

    with (
        source_engine(prepared) as engine,
        engine.connect() as conn,
        pytest.raises(DBAPIError, match="READ ONLY"),
    ):
        conn.execute(text("DELETE FROM customers"))


def test_mysql_refuses_the_same_database(prepared: str, with_key) -> None:
    from masker.config import load_rules_from_text
    from masker.engine import MaskingEngine
    from masker.errors import SafetyError
    from masker.keys import SecretKey

    with_key()
    rules = load_rules_from_text(RULES)
    key = SecretKey.from_text(os.environ["MASKER_SECRET_KEY"], origin="test")
    with pytest.raises(SafetyError, match="same database"):
        MaskingEngine(source_url=prepared, target_url=prepared, rules=rules, key=key).run()

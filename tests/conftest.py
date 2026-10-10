"""Shared fixtures.

Everything here runs on SQLite, which ships with Python, so the whole unit and
integration suite runs anywhere with no services.
"""

from __future__ import annotations

import datetime as dt
import random
import sqlite3
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from masker.config import RulesFile, load_rules_from_text
from masker.keys import SecretKey

TEST_KEY = "unit-test-key-0123456789abcdef"

SCHEMA = """
CREATE TABLE users (
    id      INTEGER PRIMARY KEY,
    email   VARCHAR(120) NOT NULL UNIQUE,
    name    VARCHAR(80) NOT NULL,
    phone   VARCHAR(24),
    ssn     VARCHAR(11) UNIQUE,
    dob     DATE,
    salary  INTEGER,
    bio     TEXT,
    active  BOOLEAN DEFAULT 1
);

CREATE TABLE accounts (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER NOT NULL UNIQUE REFERENCES users(id),
    iban        VARCHAR(34),
    created_at  TIMESTAMP NOT NULL
);

CREATE TABLE orders (
    id          INTEGER PRIMARY KEY,
    account_id  INTEGER NOT NULL REFERENCES accounts(id),
    total       NUMERIC(10, 2) NOT NULL,
    note        TEXT
);

CREATE TABLE employees (
    id          INTEGER PRIMARY KEY,
    manager_id  INTEGER REFERENCES employees(id),
    email       VARCHAR(120) NOT NULL UNIQUE
);

CREATE TABLE cyc_a (id INTEGER PRIMARY KEY, b_id INTEGER REFERENCES cyc_b(id));
CREATE TABLE cyc_b (id INTEGER PRIMARY KEY, a_id INTEGER REFERENCES cyc_a(id));
"""


@pytest.fixture(scope="session")
def key() -> SecretKey:
    return SecretKey.from_text(TEST_KEY, origin="test")


@pytest.fixture(scope="session")
def other_key() -> SecretKey:
    return SecretKey.from_text("a-completely-different-key-987654", origin="test")


@pytest.fixture
def source_db(tmp_path: Path) -> Path:
    """A small database with FKs, unique columns, a self-FK and an FK cycle."""
    path = tmp_path / "source.sqlite"
    conn = sqlite3.connect(path)
    rng = random.Random(42)
    try:
        for statement in SCHEMA.split(";"):
            if statement.strip():
                conn.execute(statement)
        for user_id in range(1, 21):
            conn.execute(
                "INSERT INTO users VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    user_id,
                    f"user{user_id}@corp.example",
                    f"Person {user_id}",
                    f"555-01{user_id:02d}",
                    f"{100 + user_id}-45-{6789 + user_id}",
                    dt.date(
                        1980 + user_id % 20, (user_id % 12) + 1, (user_id % 27) + 1
                    ).isoformat(),
                    40_000 + user_id * 1000,
                    f"User {user_id} lives at {user_id} Main St and can be reached on 555.",
                    user_id % 2 == 0,
                ),
            )
            conn.execute(
                "INSERT INTO accounts VALUES (?,?,?,?)",
                (
                    user_id,
                    user_id,
                    f"GB{user_id:02d}MOCK{user_id:08d}",
                    dt.datetime(2023, 1, 1, 10, 0, 0).isoformat(sep=" "),
                ),
            )
        order_id = 0
        for account_id in range(1, 21):
            for _ in range(rng.randint(1, 3)):
                order_id += 1
                conn.execute(
                    "INSERT INTO orders VALUES (?,?,?,?)",
                    (
                        order_id,
                        account_id,
                        round(rng.uniform(5, 500), 2),
                        "please gift wrap" if order_id % 3 == 0 else None,
                    ),
                )
        for employee_id in range(1, 7):
            conn.execute(
                "INSERT INTO employees VALUES (?,?,?)",
                (
                    employee_id,
                    None if employee_id == 1 else employee_id - 1,
                    f"employee{employee_id}@corp.example",
                ),
            )
        for index in range(1, 4):
            conn.execute("INSERT INTO cyc_a VALUES (?,?)", (index, index))
            conn.execute("INSERT INTO cyc_b VALUES (?,?)", (index, index))
        conn.commit()
    finally:
        conn.close()
    return path


@pytest.fixture
def source_url(source_db: Path) -> str:
    return f"sqlite:///{source_db}"


@pytest.fixture
def target_db(tmp_path: Path) -> Path:
    return tmp_path / "target.sqlite"


@pytest.fixture
def target_url(target_db: Path) -> str:
    return f"sqlite:///{target_db}"


@pytest.fixture
def engine(source_url: str) -> Iterator[Engine]:
    created = create_engine(source_url)
    try:
        yield created
    finally:
        created.dispose()


@pytest.fixture
def full_rules() -> RulesFile:
    return load_rules_from_text(FULL_RULES)


FULL_RULES = """
version: 1
settings:
  batch_size: 7
tables:
  users:
    columns:
      id:     {transformer: hash}
      email:  {transformer: email}
      name:   {transformer: fake, params: {provider: name}}
      phone:  {transformer: partial_mask, params: {keep_last: 4}}
      ssn:    {transformer: hash, params: {length: 11}}
      dob:    {transformer: date_shift, params: {min_days: -30, max_days: 30}}
      salary: {transformer: number_noise, params: {percent: 10}}
      bio:    {transformer: redact}
      active: {transformer: keep}
  accounts:
    columns:
      id:         {transformer: hash}
      user_id:    {transformer: hash}
      iban:       {transformer: hash, params: {length: 20}}
      created_at: {transformer: date_shift, params: {min_days: -10, max_days: 10}}
  orders:
    columns:
      id:         {transformer: hash}
      account_id: {transformer: hash}
      total:      {transformer: number_noise, params: {percent: 5, round_to: 2}}
      note:       {transformer: keep}
  employees:
    columns:
      id:         {transformer: hash}
      manager_id: {transformer: hash}
      email:      {transformer: email}
  cyc_a:
    columns:
      id:   {transformer: hash}
      b_id: {transformer: hash}
  cyc_b:
    columns:
      id:   {transformer: hash}
      a_id: {transformer: hash}
"""


@pytest.fixture
def query_target() -> Callable[[str, str], list[tuple[object, ...]]]:
    """Run a query against a database file and return all rows."""

    def run(url: str, sql: str) -> list[tuple[object, ...]]:
        database = url.replace("sqlite:///", "")
        conn = sqlite3.connect(database)
        try:
            return conn.execute(sql).fetchall()
        finally:
            conn.close()

    return run


@pytest.fixture
def scalar_target() -> Callable[[str, str], object]:
    def run(url: str, sql: str) -> object:
        rows = []
        database = url.replace("sqlite:///", "")
        conn = sqlite3.connect(database)
        try:
            rows = conn.execute(sql).fetchall()
        finally:
            conn.close()
        return rows[0][0] if rows else None

    return run


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the host environment from leaking a key into tests."""
    monkeypatch.delenv("MASKER_SECRET_KEY", raising=False)
    monkeypatch.delenv("MASKER_KEY_FILE", raising=False)


@pytest.fixture
def with_key(monkeypatch: pytest.MonkeyPatch) -> Callable[[str], None]:
    def set_key(value: str = TEST_KEY) -> None:
        monkeypatch.setenv("MASKER_SECRET_KEY", value)

    return set_key


@pytest.fixture
def sqlite_text() -> Callable[[str], str]:
    """Execute raw SQL against a file and return the first column as text."""

    def run(sql: str) -> str:
        with create_engine("sqlite://").begin() as conn:
            return str(conn.execute(text(sql)).scalar_one())

    return run

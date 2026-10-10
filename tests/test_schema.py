"""Schema reflection, foreign-key ordering and cycle detection."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

from masker.errors import SchemaError
from masker.schema import (
    ReflectedSchema,
    fk_column_namespaces,
    reflect_schema,
    row_count,
    table_groups,
)


@pytest.fixture
def schema(engine: Engine) -> ReflectedSchema:
    return reflect_schema(engine)


def test_every_table_is_reflected(schema: ReflectedSchema) -> None:
    assert set(schema.tables) == {
        "users",
        "accounts",
        "orders",
        "employees",
        "cyc_a",
        "cyc_b",
    }


def test_column_attributes(schema: ReflectedSchema) -> None:
    users = schema.get("users")
    email = users.column("email")
    assert email is not None
    assert email.length == 120
    assert not email.nullable
    assert email.is_unique
    assert not email.is_primary_key

    identifier = users.column("id")
    assert identifier is not None
    assert identifier.is_primary_key
    assert identifier.is_unique
    assert users.primary_key == ["id"]


def test_missing_column_returns_none(schema: ReflectedSchema) -> None:
    assert schema.get("users").column("nope") is None


def test_composite_primary_keys_are_not_per_column_unique(tmp_path: Path) -> None:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE t (a INTEGER, b INTEGER, PRIMARY KEY (a, b))")
    conn.commit()
    path = tmp_path / "masker-composite.sqlite"
    if path.exists():
        path.unlink()
    disk = sqlite3.connect(path)
    disk.execute("CREATE TABLE t (a INTEGER, b INTEGER, PRIMARY KEY (a, b))")
    disk.commit()
    disk.close()
    conn.close()
    try:
        engine = create_engine(f"sqlite:///{path}")
        try:
            reflected = reflect_schema(engine)
            assert reflected.get("t").unique_columns == []
        finally:
            engine.dispose()
    finally:
        path.unlink(missing_ok=True)


def test_unique_indexes_are_detected(schema: ReflectedSchema) -> None:
    assert "ssn" in schema.get("users").unique_columns


def test_foreign_keys_are_reflected(schema: ReflectedSchema) -> None:
    orders = schema.get("orders")
    assert orders.foreign_keys[0].referred_table == "accounts"
    assert orders.foreign_keys[0].columns == ("account_id",)
    assert orders.foreign_keys[0].referred_columns == ("id",)
    assert orders.referenced_tables == ["accounts"]


def test_fk_pairs(schema: ReflectedSchema) -> None:
    assert ("orders", "account_id", "accounts", "id") in schema.fk_pairs()
    assert ("employees", "manager_id", "employees", "id") in schema.fk_pairs()


def test_parents_come_before_children(schema: ReflectedSchema) -> None:
    flat = [name for group in schema.ordered_tables for name in group]
    assert flat.index("users") < flat.index("accounts")
    assert flat.index("accounts") < flat.index("orders")


def test_a_two_table_cycle_is_one_group(schema: ReflectedSchema) -> None:
    assert ["cyc_a", "cyc_b"] in schema.ordered_tables


def test_self_reference_counts_as_a_cycle(schema: ReflectedSchema) -> None:
    assert ["employees"] in schema.cycles
    assert ["cyc_a", "cyc_b"] in schema.cycles
    assert ["users"] not in schema.cycles


def test_unknown_table(schema: ReflectedSchema) -> None:
    with pytest.raises(SchemaError, match="Unknown table"):
        schema.get("nope")


def test_reflect_rejects_unknown_tables(engine: Engine) -> None:
    with pytest.raises(SchemaError, match="Unknown table"):
        reflect_schema(engine, only=["nope"])


def test_reflect_an_empty_database(tmp_path: Path) -> None:
    path = tmp_path / "empty.sqlite"
    sqlite3.connect(path).close()
    assert reflect_schema(create_engine(f"sqlite:///{path}")).tables == {}


def test_row_count(engine: Engine, schema: ReflectedSchema) -> None:
    assert row_count(engine, schema.get("users").table) == 20
    assert row_count(engine, schema.get("cyc_a").table) == 3


def test_unreachable_database_is_reported(tmp_path: Path) -> None:
    with pytest.raises(SchemaError, match="Could not inspect"):
        reflect_schema(create_engine(f"sqlite:///{tmp_path}/absent/dir.sqlite"))


# --------------------------------------------------------------------------- #
# Ordering and namespaces
# --------------------------------------------------------------------------- #
def test_ordering_an_empty_graph() -> None:
    assert table_groups({}) == []


def test_ordering_a_diamond_dependency() -> None:
    class FakeTable:
        def __init__(self, name: str, parents: list[str]) -> None:
            self.name = name
            self.referenced_tables = parents

    tables = {
        "leaf": FakeTable("leaf", ["left", "right"]),
        "left": FakeTable("left", ["root"]),
        "right": FakeTable("right", ["root"]),
        "root": FakeTable("root", []),
    }
    groups = table_groups(tables)  # type: ignore[arg-type]
    flat = [name for group in groups for name in group]
    assert flat.index("root") < flat.index("left")
    assert flat.index("root") < flat.index("right")
    assert flat.index("left") < flat.index("leaf")
    assert flat.index("right") < flat.index("leaf")


def test_fk_namespaces_group_linked_columns(schema: ReflectedSchema) -> None:
    namespaces = fk_column_namespaces(schema)
    assert namespaces[("accounts", "user_id")] == namespaces[("users", "id")]
    assert namespaces[("orders", "account_id")] == namespaces[("accounts", "id")]
    assert namespaces[("employees", "manager_id")] == namespaces[("employees", "id")]


def test_unlinked_columns_have_no_namespace(schema: ReflectedSchema) -> None:
    assert ("users", "email") not in fk_column_namespaces(schema)


def test_namespaces_are_stable_regardless_of_reflection_order(
    source_url: str,
) -> None:
    first = fk_column_namespaces(reflect_schema(create_engine(source_url)))
    second = fk_column_namespaces(reflect_schema(create_engine(source_url)))
    assert first == second

from __future__ import annotations

import os
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.types import SmallInteger, String
from typer.testing import CliRunner

from masker.cli import app
from masker.config import load_rules_from_text, validate_rules
from masker.connect import is_same_database, redact_text, redact_url, source_engine
from masker.engine import MaskingEngine, RunOptions
from masker.errors import TransformerError
from masker.keys import SecretKey
from masker.schema import ReflectedSchema, reflect_schema
from masker.transformers import build
from masker.transformers.base import ColumnContext
from masker.values import coerce
from masker.verify import verify


@pytest.fixture
def schema(engine) -> ReflectedSchema:
    return reflect_schema(engine)


def test_sqlite_uri_and_hardlink_cannot_bypass_same_database(source_db: Path, tmp_path: Path):
    normal = f"sqlite:///{source_db}"
    uri = f"sqlite:///{source_db.as_uri()}?uri=true"
    assert is_same_database(normal, uri)
    linked = tmp_path / "linked.sqlite"
    os.link(source_db, linked)
    assert is_same_database(normal, f"sqlite:///{linked}")
    with source_engine(uri) as engine, engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM users")).scalar_one() == 20


def test_query_password_is_redacted():
    assert "hunter2" not in redact_url("postgresql://user@host/db?password=hunter2")


def test_parent_only_fk_masking_warns_without_crashing(schema: ReflectedSchema):
    rules = load_rules_from_text("tables: {users: {columns: {id: {transformer: hash}}}}")
    assert any(issue.code == "fk-one-sided" for issue in validate_rules(rules, schema))


def test_invalid_hash_params_are_reported(schema: ReflectedSchema):
    rules = load_rules_from_text(
        "tables: {users: {columns: {ssn: {transformer: hash, params: {length: nope}}}}}"
    )
    assert any(issue.code == "invalid-params" for issue in validate_rules(rules, schema))


def test_fk_unique_retries_share_the_mapping(tmp_path: Path, key: SecretKey):
    source_url = f"sqlite:///{tmp_path / 'source.sqlite'}"
    target_url = f"sqlite:///{tmp_path / 'target.sqlite'}"
    source = create_engine(source_url)
    with source.begin() as conn:
        conn.execute(text("CREATE TABLE parent (id VARCHAR(2) PRIMARY KEY)"))
        conn.execute(
            text(
                "CREATE TABLE child (id INTEGER PRIMARY KEY, ref VARCHAR(2) REFERENCES parent(id))"
            )
        )
        for i in range(10):
            conn.execute(text("INSERT INTO parent VALUES (:v)"), {"v": str(i)})
            for j in range(2):
                conn.execute(
                    text("INSERT INTO child VALUES (:id, :v)"), {"id": i * 2 + j, "v": str(i)}
                )
    source.dispose()
    rules = load_rules_from_text("""
tables:
  parent:
    columns:
      id: {transformer: hash, params: {length: 1}}
  child:
    columns:
      ref: {transformer: hash, params: {length: 1}}
""")
    result = MaskingEngine(source_url=source_url, target_url=target_url, rules=rules, key=key).run()
    assert sum(t.unique_retries for t in result.tables) > 0
    target = create_engine(target_url)
    try:
        with target.connect() as conn:
            assert (
                conn.execute(
                    text(
                        "SELECT COUNT(*) FROM child c LEFT JOIN parent p "
                        "ON c.ref=p.id WHERE p.id IS NULL"
                    )
                ).scalar_one()
                == 0
            )
    finally:
        target.dispose()


def test_verify_value_sniffing_catches_unruled_opaque_email(tmp_path: Path, key: SecretKey):
    urls = [f"sqlite:///{tmp_path / name}" for name in ("source.sqlite", "target.sqlite")]
    for url in urls:
        engine = create_engine(url)
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE t (id INTEGER PRIMARY KEY, opaque TEXT)"))
            for i in range(4):
                conn.execute(
                    text("INSERT INTO t VALUES (:i,:v)"), {"i": i, "v": f"person{i}@corp.example"}
                )
        engine.dispose()
    result = verify(
        source_url=urls[0], target_url=urls[1], rules=load_rules_from_text("tables: {}"), key=key
    )
    assert not result.ok
    assert any(check.column == "opaque" for check in result.unmasked_pii)


def test_shuffle_has_no_fixed_points_and_rejects_singletons(key: SecretKey):
    ctx = ColumnContext("t", "c", key, String())
    transformer = build("shuffle", {}, ctx)
    values = list("abcdefgh")
    transformer.prepare(values)
    assert all(transformer(value) != value for value in values)
    with pytest.raises(TransformerError, match="one distinct value"):
        transformer.prepare(["only"])


def test_smallint_hash_fits_and_fractional_decimal_is_rejected(key: SecretKey):
    transformer = build("hash", {}, ColumnContext("t", "id", key, SmallInteger()))
    assert all(0 <= transformer(i) < 2**15 for i in range(100))
    with pytest.raises(ValueError, match="whole number"):
        coerce(Decimal("1.25"), int)


def test_skip_preserves_existing_target_rows(tmp_path: Path, key: SecretKey):
    source_url = f"sqlite:///{tmp_path / 'source.sqlite'}"
    target_url = f"sqlite:///{tmp_path / 'target.sqlite'}"
    for url in (source_url, target_url):
        engine = create_engine(url)
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE t (id INTEGER PRIMARY KEY)"))
            conn.execute(text("INSERT INTO t VALUES (1)"))
        engine.dispose()
    MaskingEngine(
        source_url=source_url,
        target_url=target_url,
        rules=load_rules_from_text("tables: {t: skip}"),
        key=key,
        options=RunOptions(allow_non_empty=True),
    ).run()
    target = create_engine(target_url)
    try:
        with target.connect() as conn:
            assert conn.execute(text("SELECT COUNT(*) FROM t")).scalar_one() == 1
    finally:
        target.dispose()


def test_init_exclude_without_tables(source_url: str, tmp_path: Path):
    output = tmp_path / "rules.yaml"
    result = CliRunner().invoke(
        app, ["init", "--source", source_url, "--exclude", "users", "--output", str(output)]
    )
    assert result.exit_code == 0, result.output
    assert "users" not in load_rules_from_text(output.read_text(encoding="utf-8")).tables


def test_cli_rejects_zero_batch_size():
    result = CliRunner().invoke(
        app, ["run", "--source", "sqlite://", "--target", "sqlite://", "--batch-size", "0"]
    )
    assert result.exit_code == 2


def test_key_repr_does_not_expose_material(key: SecretKey):
    assert key.material.decode() not in repr(key)


def test_quoted_passwords_are_redacted():
    assert "hunter two" not in redact_text('password="hunter two" host=db')
    assert "hunter two" not in redact_text("password='hunter two' host=db")

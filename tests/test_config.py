"""Rules file parsing, validation and compilation."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from masker.config import (
    RulesFile,
    assert_no_errors,
    compile_rules,
    load_rules,
    load_rules_from_text,
    validate_rules,
)
from masker.errors import ConfigError, TransformerError
from masker.keys import SecretKey
from masker.schema import ReflectedSchema, reflect_schema

MINIMAL = """
version: 1
tables:
  users:
    columns:
      email: {transformer: email}
"""


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def test_loads_a_minimal_file() -> None:
    rules = load_rules_from_text(MINIMAL)
    assert rules.version == 1
    assert rules.settings.batch_size == 5000
    assert rules.tables["users"].columns["email"].transformer == "email"


def test_loads_from_a_path(tmp_path: Path) -> None:
    path = tmp_path / "masker.yaml"
    path.write_text(MINIMAL, encoding="utf-8")
    assert load_rules(path).tables["users"].action == "copy"


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Rules file not found"):
        load_rules(tmp_path / "absent.yaml")


def test_empty_file() -> None:
    with pytest.raises(ConfigError, match="is empty"):
        load_rules_from_text("")


def test_non_mapping_root() -> None:
    with pytest.raises(ConfigError, match="must be a mapping"):
        load_rules_from_text("- one\n- two\n")


def test_invalid_yaml_reports_the_parser_error() -> None:
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_rules_from_text("tables: [unclosed\n")


def test_unknown_setting_is_rejected() -> None:
    with pytest.raises(ConfigError, match=r"settings\.batch_siz"):
        load_rules_from_text("settings: {batch_siz: 5}\n")


def test_unknown_table_key_is_rejected() -> None:
    with pytest.raises(ConfigError, match=r"tables\.users\.extra"):
        load_rules_from_text("tables:\n  users: {action: copy, columns: {}, extra: 1}\n")


def test_bad_version_is_rejected() -> None:
    with pytest.raises(ConfigError, match="version"):
        load_rules_from_text("version: 2\n")


def test_string_shorthand_for_a_transformer() -> None:
    rules = load_rules_from_text("tables:\n  users:\n    columns:\n      email: email\n")
    assert rules.tables["users"].columns["email"].transformer == "email"


def test_null_shorthand_means_keep() -> None:
    rules = load_rules_from_text("tables:\n  users:\n    columns:\n      email:\n")
    assert rules.tables["users"].columns["email"].transformer == "keep"


def test_string_shorthand_for_a_table_action() -> None:
    rules = load_rules_from_text("tables:\n  audit_log: skip\n")
    assert rules.tables["audit_log"].action == "skip"


def test_subset_rows_must_be_positive() -> None:
    with pytest.raises(ConfigError, match="subset_rows"):
        load_rules_from_text("tables:\n  users: {action: subset, subset_rows: 0}\n")


# --------------------------------------------------------------------------- #
# Validation against the schema
# --------------------------------------------------------------------------- #
@pytest.fixture
def schema(engine: Engine) -> ReflectedSchema:
    return reflect_schema(engine)


def test_clean_rules_produce_no_errors(schema: ReflectedSchema, key: SecretKey) -> None:
    rules = load_rules_from_text(
        """
        tables:
          users:
            columns:
              email: {transformer: email}
              id:    {transformer: hash}
          accounts:
            columns:
              user_id: {transformer: hash}
        """
    )
    issues = validate_rules(rules, schema)
    assert_no_errors(issues)
    codes = {issue.code for issue in issues}
    assert "unknown-table" not in codes


def test_unknown_table(schema: ReflectedSchema) -> None:
    issues = validate_rules(load_rules_from_text("tables:\n  nope: {action: copy}\n"), schema)
    assert any(issue.code == "unknown-table" for issue in issues)
    with pytest.raises(ConfigError, match="1 problem"):
        assert_no_errors(issues)


def test_unknown_column(schema: ReflectedSchema) -> None:
    rules = load_rules_from_text(
        "tables:\n  users:\n    columns:\n      nope: {transformer: email}\n"
    )
    assert any(issue.code == "unknown-column" for issue in validate_rules(rules, schema))


def test_unknown_transformer(schema: ReflectedSchema) -> None:
    rules = load_rules_from_text(
        "tables:\n  users:\n    columns:\n      email: {transformer: nosuch}\n"
    )
    assert any(issue.code == "unknown-transformer" for issue in validate_rules(rules, schema))


def test_unknown_order_by(schema: ReflectedSchema) -> None:
    rules = load_rules_from_text("tables:\n  users: {order_by: [nope]}\n")
    assert any(issue.code == "unknown-order-by" for issue in validate_rules(rules, schema))


def test_subset_without_a_row_count_warns(schema: ReflectedSchema) -> None:
    rules = load_rules_from_text("tables:\n  users: {action: subset}\n")
    assert any(issue.code == "subset-without-rows" for issue in validate_rules(rules, schema))


def test_skip_and_truncate_are_reported_as_notes(schema: ReflectedSchema) -> None:
    rules = load_rules_from_text("tables:\n  users: skip\n  accounts: truncate\n")
    notes = [i for i in validate_rules(rules, schema) if i.severity == "info"]
    assert len(notes) == 2


def test_text_transformer_on_a_numeric_column_is_an_error(schema: ReflectedSchema) -> None:
    rules = load_rules_from_text(
        "tables:\n  users:\n    columns:\n      salary: {transformer: email}\n"
    )
    issues = validate_rules(rules, schema)
    assert any(issue.code == "type-mismatch" and issue.severity == "error" for issue in issues)


def test_date_shift_on_a_numeric_column_is_an_error(schema: ReflectedSchema) -> None:
    rules = load_rules_from_text(
        "tables:\n  users:\n    columns:\n      salary: {transformer: date_shift}\n"
    )
    assert any(issue.code == "type-mismatch" for issue in validate_rules(rules, schema))


def test_email_on_a_date_column_is_an_error(schema: ReflectedSchema) -> None:
    # The masked value would not fit the column, so this is caught up front.
    rules = load_rules_from_text(
        "tables:\n  users:\n    columns:\n      dob: {transformer: email}\n"
    )
    issues = validate_rules(rules, schema)
    assert any(issue.code == "type-mismatch" and issue.severity == "error" for issue in issues)


def test_hash_longer_than_the_column_warns(schema: ReflectedSchema) -> None:
    rules = load_rules_from_text(
        "tables:\n  users:\n    columns:\n      ssn: {transformer: hash, params: {length: 40}}\n"
    )
    assert any(issue.code == "value-too-long" for issue in validate_rules(rules, schema))


def test_partial_mask_wider_than_the_column_warns(schema: ReflectedSchema) -> None:
    rules = load_rules_from_text(
        "tables:\n  users:\n    columns:\n      ssn: "
        "{transformer: partial_mask, params: {keep_first: 9, keep_last: 9}}\n"
    )
    assert any(issue.code == "partial-mask-too-wide" for issue in validate_rules(rules, schema))


def test_constant_on_a_unique_column_is_an_error(schema: ReflectedSchema) -> None:
    rules = load_rules_from_text(
        "tables:\n  users:\n    columns:\n      email: {transformer: redact}\n"
    )
    issues = validate_rules(rules, schema)
    assert any(issue.code == "uniqueness-impossible" for issue in issues)


def test_fk_masked_on_one_side_only_warns(schema: ReflectedSchema) -> None:
    rules = load_rules_from_text(
        """
        tables:
          accounts:
            columns:
              user_id: {transformer: hash}
        """
    )
    issues = validate_rules(rules, schema)
    assert any(issue.code == "fk-one-sided" for issue in issues)


def test_fk_with_different_transformers_warns(schema: ReflectedSchema) -> None:
    rules = load_rules_from_text(
        """
        tables:
          users:
            columns:
              id: {transformer: hash}
          accounts:
            columns:
              user_id: {transformer: shuffle}
        """
    )
    issues = validate_rules(rules, schema)
    assert any(issue.code == "fk-transformer-mismatch" for issue in issues)


def test_fk_namespaces_must_agree(schema: ReflectedSchema) -> None:
    rules = load_rules_from_text(
        """
        tables:
          users:
            columns:
              id: {transformer: hash, namespace: users.id}
          accounts:
            columns:
              user_id: {transformer: hash}
        """
    )
    assert any(issue.code == "fk-namespace-mismatch" for issue in validate_rules(rules, schema))


def test_unruled_columns_are_listed(schema: ReflectedSchema) -> None:
    rules = load_rules_from_text("tables:\n  users:\n    columns: {}\n")
    unruled = [i for i in validate_rules(rules, schema) if i.code == "no-rule"]
    assert {issue.column for issue in unruled} == {
        "id",
        "email",
        "name",
        "phone",
        "ssn",
        "dob",
        "salary",
        "bio",
        "active",
    }


def test_skipped_tables_have_no_unruled_columns(schema: ReflectedSchema) -> None:
    rules = load_rules_from_text("tables:\n  users: skip\n")
    assert not [i for i in validate_rules(rules, schema) if i.code == "no-rule"]


def test_issue_where_falls_back_to_the_table(schema: ReflectedSchema) -> None:
    issues = validate_rules(load_rules_from_text("tables:\n  nope: {action: copy}\n"), schema)
    assert issues[0].where == "nope"
    assert issues[0].hint is not None


# --------------------------------------------------------------------------- #
# Compilation
# --------------------------------------------------------------------------- #
def test_compile_binds_a_transformer_per_column(
    schema: ReflectedSchema, full_rules: RulesFile, key: SecretKey
) -> None:
    plan = compile_rules(full_rules, schema, key)
    users = plan.get("users")
    assert set(users.masked_columns) == {
        "id",
        "email",
        "name",
        "phone",
        "ssn",
        "dob",
        "salary",
        "bio",
    }
    assert users.unmasked_columns == ["active"]
    assert users.copies_rows


def test_compile_rejects_an_unknown_transformer(schema: ReflectedSchema, key: SecretKey) -> None:
    rules = load_rules_from_text(
        "tables:\n  users:\n    columns:\n      email: {transformer: nosuch}\n"
    )
    with pytest.raises(TransformerError, match="Unknown transformer"):
        compile_rules(rules, schema, key)


def test_compile_respects_only(
    schema: ReflectedSchema, full_rules: RulesFile, key: SecretKey
) -> None:
    plan = compile_rules(full_rules, schema, key, only=["users"])
    assert set(plan.tables) == {"users"}
    assert plan.copied_tables == ["users"]


def test_compile_keeps_the_dependency_order(
    schema: ReflectedSchema, full_rules: RulesFile, key: SecretKey
) -> None:
    plan = compile_rules(full_rules, schema, key)
    flat = [name for group in plan.order for name in group if name in plan.tables]
    assert flat.index("users") < flat.index("accounts")
    assert flat.index("accounts") < flat.index("orders")


def test_on_null_transform_is_honoured(schema: ReflectedSchema, key: SecretKey) -> None:
    rules = load_rules_from_text(
        """
        settings: {null_passthrough: true}
        tables:
          users:
            columns:
              name: {transformer: constant, params: {value: x}, on_null: transform}
        """
    )
    plan = compile_rules(rules, schema, key)
    assert plan.get("users").masked_columns["name"](None) == "x"


def test_unique_can_be_overridden(schema: ReflectedSchema, key: SecretKey) -> None:
    rules = load_rules_from_text(
        "tables:\n  users:\n    columns:\n      email: {transformer: hash, unique: false}\n"
    )
    plan = compile_rules(rules, schema, key)
    assert not plan.get("users").masked_columns["email"].ctx.is_unique


def test_table_subset_rows_fall_back_to_settings(schema: ReflectedSchema, key: SecretKey) -> None:
    rules = load_rules_from_text("settings: {subset_rows: 5}\ntables:\n  users: {action: subset}\n")
    assert compile_rules(rules, schema, key).get("users").subset_rows == 5


def test_truncate_does_not_copy_rows(schema: ReflectedSchema, key: SecretKey) -> None:
    rules = load_rules_from_text("tables:\n  users: truncate\n")
    assert not compile_rules(rules, schema, key).get("users").copies_rows


def test_rules_file_defaults_are_usable() -> None:
    assert RulesFile().tables == {}

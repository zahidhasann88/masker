"""PII heuristics: name patterns, value sniffing and the scan gate."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from masker.config import load_rules_from_text
from masker.scan import (
    NON_GATING_CATEGORIES,
    ColumnFinding,
    _looks_like_card,
    _looks_like_free_text,
    _looks_like_ipv4,
    _looks_like_phone,
    _looks_like_url,
    match_name,
    name_patterns,
    scan_schema,
)
from masker.schema import ReflectedSchema


@pytest.fixture
def schema(engine: Engine) -> ReflectedSchema:
    from masker.schema import reflect_schema

    return reflect_schema(engine)


# --------------------------------------------------------------------------- #
# Name patterns
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("column", "category"),
    [
        ("email", "email"),
        ("user_email_address", "email"),
        ("full_name", "person"),
        ("first_name", "person"),
        ("lastname", "person"),
        ("phone_number", "phone"),
        ("mobile", "phone"),
        ("ssn", "government-id"),
        ("social_security_number", "government-id"),
        ("national_id", "government-id"),
        ("passport_no", "government-id"),
        ("tax_id", "government-id"),
        ("credit_card", "card"),
        ("card_number", "card"),
        ("iban", "financial"),
        ("bank_account_number", "financial"),
        ("date_of_birth", "birthdate"),
        ("dob", "birthdate"),
        ("birth_date", "birthdate"),
        ("street_address", "address"),
        ("zip_code", "address"),
        ("postal_code", "address"),
        ("ip_address", "network"),
        ("ipv6", "network"),
        ("user_agent", "device"),
        ("device_id", "device"),
        ("latitude", "location"),
        ("longitude", "location"),
        ("salary", "financial"),
        ("annual_income", "financial"),
        ("account_balance", "financial"),
        ("notes", "free-text"),
        ("comment_body", "free-text"),
        ("homepage_url", "reference"),
    ],
)
def test_name_patterns_match_the_obvious(column: str, category: str) -> None:
    pattern = match_name(column)
    assert pattern is not None, column
    assert pattern.category == category


@pytest.mark.parametrize("column", ["id", "created_at", "quantity", "total", "sku", "is_active"])
def test_innocuous_names_are_not_flagged_as_pii(column: str) -> None:
    pattern = match_name(column)
    assert pattern is None or pattern.confidence == "low"


def test_patterns_are_unique() -> None:
    patterns = [pattern.pattern for pattern in name_patterns()]
    assert len(patterns) == len(set(patterns))


def test_every_pattern_has_a_transformer_and_category() -> None:
    for pattern in name_patterns():
        assert pattern.transformer
        assert pattern.category
        assert pattern.confidence in ("low", "medium", "high")
        assert isinstance(pattern.params, dict)


def test_matching_is_case_insensitive() -> None:
    assert match_name("EMAIL") is not None
    assert match_name("Email_Address") is not None


def test_free_text_is_not_a_gating_category() -> None:
    assert "free-text" in NON_GATING_CATEGORIES
    assert "email" not in NON_GATING_CATEGORIES


# --------------------------------------------------------------------------- #
# Value sniffing
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "value",
    ["4111111111111111", "4111 1111 1111 1111", "4111-1111-1111-1111", "5500000000000004"],
)
def test_valid_cards_are_detected(value: str) -> None:
    assert _looks_like_card(value)


@pytest.mark.parametrize("value", ["4111111111111112", "1234567890123456", "not-a-card"])
def test_invalid_cards_are_rejected(value: str) -> None:
    assert not _looks_like_card(value)


@pytest.mark.parametrize("value", ["+1 (555) 010-1234", "555-0100", "+44 20 7946 0958"])
def test_phone_shapes_are_detected(value: str) -> None:
    assert _looks_like_phone(value)


@pytest.mark.parametrize("value", ["1234", "2024-01-15", "see order 5551234 for details"])
def test_non_phones_are_rejected(value: str) -> None:
    assert not _looks_like_phone(value)


@pytest.mark.parametrize("value", ["192.168.1.1", "10.0.0.255"])
def test_ipv4_is_detected(value: str) -> None:
    assert _looks_like_ipv4(value)


@pytest.mark.parametrize("value", ["256.1.1.1", "1.2.3", "not an ip"])
def test_ipv4_false_positives_are_rejected(value: str) -> None:
    assert not _looks_like_ipv4(value)


@pytest.mark.parametrize("value", ["https://example.com/me", "http://a.b/c?d=1"])
def test_urls_are_detected(value: str) -> None:
    assert _looks_like_url(value)


@pytest.mark.parametrize("value", ["ftp://example.com", "example.com"])
def test_non_http_urls_are_rejected(value: str) -> None:
    assert not _looks_like_url(value)


def test_free_text_needs_several_words() -> None:
    long_text = "The quick brown fox jumps over the lazy dog, " * 2
    assert _looks_like_free_text(long_text)
    assert not _looks_like_free_text("Jane")
    assert not _looks_like_free_text(None)
    assert not _looks_like_free_text(42)


# --------------------------------------------------------------------------- #
# Whole-schema scan
# --------------------------------------------------------------------------- #
def test_scan_flags_the_demo_schema(engine: Engine, schema: ReflectedSchema) -> None:
    result = scan_schema(engine, schema)
    labels = {finding.label for finding in result.suspected_pii}
    assert "users.email" in labels
    assert "users.ssn" in labels
    assert "users.dob" in labels
    assert "users.name" in labels
    assert result.tables_scanned == 6
    assert result.rows_sampled > 0


def test_scan_lists_columns_without_a_rule(engine: Engine, schema: ReflectedSchema) -> None:
    result = scan_schema(engine, schema)
    assert ("users", "email") in result.unruled


def test_rules_mark_columns_as_handled(engine: Engine, schema: ReflectedSchema) -> None:
    rules = load_rules_from_text(
        """
        tables:
          users:
            columns:
              email: {transformer: email}
              ssn:   {transformer: hash}
              name:  {transformer: fake, params: {provider: name}}
              dob:   {transformer: date_shift}
        """
    )
    result = scan_schema(engine, schema, rules)
    handled = {finding.label for finding in result.findings if not finding.unmasked}
    assert {"users.email", "users.ssn"} <= handled


def test_a_passthrough_rule_is_still_considered_unmasked(
    engine: Engine, schema: ReflectedSchema
) -> None:
    rules = load_rules_from_text("tables:\n  users:\n    columns:\n      email: keep\n")
    result = scan_schema(engine, schema, rules)
    finding = next(f for f in result.findings if f.label == "users.email")
    # It really is copied verbatim...
    assert finding.unmasked
    # ...but it is a reviewed decision, so it does not fail --strict. `verify`
    # draws the same line; the two commands must not disagree.
    assert finding.explicit
    assert finding.label not in {f.label for f in result.unmasked_suspected_pii}
    # Other columns here have no rule at all, so the gate still fails.
    assert not result.ok


def test_an_explicit_keep_is_the_only_thing_gating(engine: Engine, schema: ReflectedSchema) -> None:
    # Mask everything except `users.email`, which is an explicit keep: the run
    # must be considered clean.
    rules = load_rules_from_text(
        """
        tables:
          users:
            columns:
              email:  keep
              name:   {transformer: fake, params: {provider: name}}
              phone:  {transformer: partial_mask}
              ssn:    {transformer: hash}
              dob:    {transformer: date_shift}
              salary: {transformer: number_noise}
              bio:    {transformer: redact}
          accounts:
            columns:
              iban: {transformer: hash}
          employees:
            columns:
              email: {transformer: email}
        """
    )
    result = scan_schema(engine, schema, rules)
    assert result.ok, [f.label for f in result.unmasked_suspected_pii]


def test_strict_gate_ignores_skipped_tables(engine: Engine, schema: ReflectedSchema) -> None:
    rules = load_rules_from_text("tables:\n  users: skip\n")
    result = scan_schema(engine, schema, rules)
    assert not any(label.startswith("users.") for label, _ in result.unruled)
    assert result.tables_scanned == 5


def test_scan_can_be_limited_to_some_tables(engine: Engine, schema: ReflectedSchema) -> None:
    result = scan_schema(engine, schema, tables=["users"])
    assert result.tables_scanned == 1
    assert all(finding.table == "users" for finding in result.findings)


def test_sample_size_limits_the_rows_read(engine: Engine, schema: ReflectedSchema) -> None:
    result = scan_schema(engine, schema, tables=["users"], sample_size=3)
    assert result.rows_sampled == 3


def test_empty_schema_scans_cleanly(tmp_path: Path) -> None:
    import sqlite3

    from sqlalchemy import create_engine

    path = tmp_path / "masker-empty-scan.sqlite"
    sqlite3.connect(path).close()
    engine = create_engine(f"sqlite:///{path}")
    try:
        from masker.schema import reflect_schema

        result = scan_schema(engine, reflect_schema(engine))
        assert result.findings == ()
        assert result.ok
    finally:
        engine.dispose()
        path.unlink(missing_ok=True)


def test_value_sniffing_detects_cards_the_name_missed(
    engine: Engine, schema: ReflectedSchema
) -> None:
    finding = ColumnFinding(
        table="t",
        column="opaque",
        category="",
        transformer="",
        params={},
        detected_by="value",
        confidence="high",
        has_rule=False,
    )
    assert finding.unmasked
    assert finding.label == "t.opaque"

"""Leak detection, the unruled-column gate and FK integrity checks."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.engine import create_engine

from masker.config import RulesFile, load_rules_from_text
from masker.engine import MaskingEngine
from masker.errors import MaskerError
from masker.keys import SecretKey
from masker.verify import (
    COLLISION_FAILURE_RATE,
    ColumnCheck,
    OrphanCheck,
    UnruledCheck,
    VerifyResult,
    verify,
)


def run_masking(source_url: str, target_url: str, rules: RulesFile, key: SecretKey) -> None:
    MaskingEngine(source_url=source_url, target_url=target_url, rules=rules, key=key).run()


# --------------------------------------------------------------------------- #
# A clean run verifies clean
# --------------------------------------------------------------------------- #
def test_a_clean_run_has_no_leaks(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    run_masking(source_url, target_url, full_rules, key)
    result = verify(source_url=source_url, target_url=target_url, rules=full_rules, key=key)
    assert result.leaks == ()
    assert result.broken_fks == ()
    assert result.unmasked_pii == ()
    assert result.ok
    assert result.total_leaked == 0
    assert sum(check.sampled for check in result.checks) > 0


def test_every_masked_column_is_checked(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    run_masking(source_url, target_url, full_rules, key)
    result = verify(source_url=source_url, target_url=target_url, rules=full_rules, key=key)
    labels = {check.label for check in result.checks}
    assert "users.email" in labels
    assert "users.ssn" in labels
    # passthrough rules are copied verbatim on purpose, so they are not leaks
    assert "users.active" not in labels
    assert "orders.note" not in labels


def test_domain_preserving_transformers_are_not_called_leaks(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    run_masking(source_url, target_url, full_rules, key)
    result = verify(source_url=source_url, target_url=target_url, rules=full_rules, key=key)
    for check in result.coincidences:
        assert check.preserves_domain
        assert check.severity == "warn"
        assert check.rate < COLLISION_FAILURE_RATE
    assert result.ok


# --------------------------------------------------------------------------- #
# A real leak is caught
# --------------------------------------------------------------------------- #
def test_a_column_left_untouched_is_reported(
    source_url: str, target_url: str, key: SecretKey
) -> None:
    # email is copied verbatim, so every original is present in the target.
    # Nothing was transformed there, so the unruled gate is what catches it.
    rules = load_rules_from_text(
        "tables:\n  users:\n    columns:\n      name: {transformer: fake, "
        "params: {provider: name}}\n"
    )
    run_masking(source_url, target_url, rules, key)
    result = verify(source_url=source_url, target_url=target_url, rules=rules, key=key)
    assert not result.ok
    flagged = next(entry for entry in result.unmasked_pii if entry.label == "users.email")
    assert flagged.severity == "error"
    assert flagged.suspected_pii
    assert flagged.rows == 20


def test_a_rule_deleted_after_the_run_is_reported(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    run_masking(source_url, target_url, full_rules, key)
    # Now pretend the rule was never there: verify must notice the omission
    # rather than declaring the run clean.
    reduced = full_rules.model_copy(deep=True)
    del reduced.tables["users"].columns["email"]
    result = verify(source_url=source_url, target_url=target_url, rules=reduced, key=key)
    assert any(entry.label == "users.email" for entry in result.unmasked_pii)
    assert not result.ok


def test_verify_can_be_limited_to_some_tables(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    run_masking(source_url, target_url, full_rules, key)
    result = verify(
        source_url=source_url,
        target_url=target_url,
        rules=full_rules,
        key=key,
        tables=["users"],
    )
    assert all(check.table == "users" for check in result.checks)


def test_fk_checks_can_be_skipped(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    run_masking(source_url, target_url, full_rules, key)
    result = verify(
        source_url=source_url,
        target_url=target_url,
        rules=full_rules,
        key=key,
        check_fk=False,
    )
    assert result.orphans == ()


def test_a_broken_foreign_key_is_reported(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    run_masking(source_url, target_url, full_rules, key)
    # Point an order at an account that does not exist.
    target = create_engine(target_url)
    try:
        with target.begin() as conn:
            conn.execute(
                text(
                    "UPDATE orders SET account_id = 999999 WHERE id = (SELECT MIN(id) FROM orders)"
                )
            )
    finally:
        target.dispose()
    result = verify(source_url=source_url, target_url=target_url, rules=full_rules, key=key)
    assert not result.ok
    assert any(orphan.label.startswith("orders.account_id") for orphan in result.broken_fks)
    assert result.broken_fks[0].orphans >= 1


def test_a_missing_target_table_is_rejected(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    run_masking(source_url, target_url, full_rules, key)
    target = create_engine(target_url)
    try:
        with target.begin() as conn:
            conn.execute(text("DROP TABLE orders"))
    finally:
        target.dispose()
    with pytest.raises(MaskerError, match="missing copied table"):
        verify(source_url=source_url, target_url=target_url, rules=full_rules, key=key)


def test_urls_are_recorded_on_the_result(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    run_masking(source_url, target_url, full_rules, key)
    result = verify(source_url=source_url, target_url=target_url, rules=full_rules, key=key)
    assert result.source == source_url
    assert result.target == target_url


def test_an_unreachable_source_is_reported(
    target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    with pytest.raises(MaskerError, match="Could not inspect"):
        verify(
            source_url="sqlite:////nonexistent/dir/source.sqlite",
            target_url=target_url,
            rules=full_rules,
            key=key,
        )


# --------------------------------------------------------------------------- #
# Serialisation
# --------------------------------------------------------------------------- #
def test_result_serialises(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    run_masking(source_url, target_url, full_rules, key)
    result = verify(source_url=source_url, target_url=target_url, rules=full_rules, key=key)
    payload = result.to_dict()
    assert payload["ok"] is True
    assert payload["total_leaked_values"] == 0
    assert payload["columns_checked"] > 0
    assert payload["leaks"] == []
    assert payload["broken_foreign_keys"] == []
    assert "unruled_columns" in payload
    assert "expected_coincidences" in payload


# --------------------------------------------------------------------------- #
# Dataclass behaviour (no database needed)
# --------------------------------------------------------------------------- #
def test_column_check_severity() -> None:
    ok = ColumnCheck(table="t", column="c", transformer="hash", sampled=10, leaked=0)
    assert ok.severity == "ok"
    assert ok.ok
    assert ok.rate == 0.0

    coincidence = ColumnCheck(
        table="t",
        column="c",
        transformer="date_shift",
        sampled=100,
        leaked=4,
        preserves_domain=True,
    )
    assert coincidence.severity == "warn"
    assert coincidence.ok
    assert coincidence.rate == 0.04

    leak = ColumnCheck(
        table="t",
        column="c",
        transformer="date_shift",
        sampled=10,
        leaked=9,
        preserves_domain=True,
    )
    assert leak.severity == "error"
    assert not leak.ok

    hard_leak = ColumnCheck(table="t", column="c", transformer="hash", sampled=10, leaked=1)
    assert hard_leak.severity == "error"


def test_column_check_handles_an_empty_sample() -> None:
    check = ColumnCheck(table="t", column="c", transformer="hash", sampled=0, leaked=0)
    assert check.rate == 0.0
    assert check.severity == "ok"


def test_column_check_label() -> None:
    assert (
        ColumnCheck(table="users", column="email", transformer="email", sampled=1, leaked=0).label
        == "users.email"
    )


def test_unruled_check_severity() -> None:
    assert UnruledCheck(table="t", column="email", rows=5, suspected_pii=True).severity == "error"
    reviewed = UnruledCheck(table="t", column="email", rows=5, suspected_pii=True, explicit=True)
    assert reviewed.severity == "warn"
    plain = UnruledCheck(table="t", column="total", rows=5, suspected_pii=False)
    assert plain.severity == "warn"
    assert plain.label == "t.total"


def test_orphan_check() -> None:
    clean = OrphanCheck(
        table="orders",
        column="account_id",
        referred_table="accounts",
        referred_column="id",
        orphans=0,
    )
    assert clean.ok
    assert clean.label == "orders.account_id -> accounts.id"
    broken = OrphanCheck(
        table="orders",
        column="account_id",
        referred_table="accounts",
        referred_column="id",
        orphans=3,
    )
    assert not broken.ok


def test_empty_verify_result_is_ok() -> None:
    result = VerifyResult(checks=(), orphans=(), unruled=(), source="a", target="b")
    assert result.ok
    assert result.total_leaked == 0
    payload = result.to_dict()
    assert payload["columns_checked"] == 0
    assert payload["total_leaked_values"] == 0
    assert payload["broken_foreign_keys"] == []
    assert payload["unruled_columns"] == []
    assert payload["expected_coincidences"] == []

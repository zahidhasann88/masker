"""The masking pipeline: ordering, batching, determinism, safety and cycles."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine

from masker.config import RulesFile, compile_rules, load_rules_from_text
from masker.engine import MaskingEngine, RunOptions
from masker.errors import SafetyError, SchemaError
from masker.keys import SecretKey
from masker.schema import reflect_schema


def make_engine_for(
    source_url: str,
    target_url: str,
    rules: RulesFile,
    key: SecretKey,
    **options: object,
) -> MaskingEngine:
    return MaskingEngine(
        source_url=source_url,
        target_url=target_url,
        rules=rules,
        key=key,
        options=RunOptions(**options),  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------- #
# Running
# --------------------------------------------------------------------------- #
def test_run_copies_and_masks(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    result = make_engine_for(source_url, target_url, full_rules, key).run()
    assert result.rows_read == result.rows_written == 89
    assert result.masked_column_count == 22
    assert not result.dry_run
    assert result.created_schema

    engine = create_engine(target_url)
    try:
        with engine.connect() as conn:
            emails = {row for (row,) in conn.execute(text("SELECT email FROM users"))}
        assert len(emails) == 20
        assert not any(email.endswith("@example.com") for email in emails)
    finally:
        engine.dispose()


def test_run_is_deterministic_across_batch_sizes(
    source_url: str, tmp_path: Path, full_rules: RulesFile, key: SecretKey
) -> None:
    targets = []
    for batch_size in (1, 7, 5000):
        target = f"sqlite:///{tmp_path}/det-{batch_size}.sqlite"
        make_engine_for(source_url, target, full_rules, key, batch_size=batch_size).run()
        targets.append(target)

    def snapshot(url: str) -> list[tuple[object, ...]]:
        engine = create_engine(url)
        try:
            with engine.connect() as conn:
                return sorted(
                    (str(row) for row in conn.execute(text("SELECT * FROM users"))),
                )
        finally:
            engine.dispose()

    assert snapshot(targets[0]) == snapshot(targets[1]) == snapshot(targets[2])


def test_run_reports_progress(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    class Recorder:
        def __init__(self) -> None:
            self.started: list[tuple[str, int | None]] = []
            self.advanced: list[int] = []
            self.done: list[tuple[str, int, float]] = []

        def table_started(self, name: str, total: int | None) -> None:
            self.started.append((name, total))

        def advance(self, rows: int) -> None:
            self.advanced.append(rows)

        def table_done(self, name: str, rows: int, seconds: float) -> None:
            self.done.append((name, rows, seconds))

    recorder = Recorder()
    MaskingEngine(
        source_url=source_url,
        target_url=target_url,
        rules=full_rules,
        key=key,
        options=RunOptions(batch_size=3),
        progress=recorder,
    ).run()
    assert ("users", 20) in recorder.started
    assert sum(recorder.advanced) == 89
    assert len(recorder.done) == 6


def test_foreign_keys_still_resolve_after_a_run(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    make_engine_for(source_url, target_url, full_rules, key).run()
    engine = create_engine(target_url)
    try:
        with engine.connect() as conn:
            orphans = conn.execute(
                text(
                    "SELECT COUNT(*) FROM orders o LEFT JOIN accounts a ON o.account_id = a.id "
                    "WHERE a.id IS NULL"
                )
            ).scalar_one()
            self_orphans = conn.execute(
                text(
                    "SELECT COUNT(*) FROM employees e LEFT JOIN employees m "
                    "ON e.manager_id = m.id "
                    "WHERE e.manager_id IS NOT NULL AND m.id IS NULL"
                )
            ).scalar_one()
        assert orphans == 0
        assert self_orphans == 0
    finally:
        engine.dispose()


def test_unique_columns_stay_unique(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    result = make_engine_for(source_url, target_url, full_rules, key).run()
    assert result.rows_written == 89
    engine = create_engine(target_url)
    try:
        with engine.connect() as conn:
            emails = [row for (row,) in conn.execute(text("SELECT email FROM users"))]
            ssns = [row for (row,) in conn.execute(text("SELECT ssn FROM users"))]
        assert len(set(emails)) == len(emails)
        assert len(set(ssns)) == len(ssns)
    finally:
        engine.dispose()


def test_unique_retries_are_counted(source_url: str, target_url: str, key: SecretKey) -> None:
    # A transformer whose first choice is always taken must retry, and the
    # retries have to surface in the run summary. cyc_a holds three rows, so
    # rows two and three need one and two retries respectively.
    from masker.transformers.base import BaseParams, BaseTransformer
    from masker.transformers.registry import REGISTRY

    class Ladder(BaseTransformer[BaseParams]):
        name = "test-ladder"
        summary = "test helper"
        params_model = BaseParams

        def _apply(self, value: object, attempt: int) -> int:
            return attempt % 4

    REGISTRY.register(Ladder)
    rules = load_rules_from_text(
        "tables:\n  cyc_a:\n    columns:\n      id: {transformer: test-ladder}\n"
    )
    result = make_engine_for(source_url, target_url, rules, key).run()
    cyc_a = next(table for table in result.tables if table.table == "cyc_a")
    assert cyc_a.unique_retries == 3


def test_subset_rows_limits_the_copy(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    result = make_engine_for(source_url, target_url, full_rules, key, subset_rows=5).run()
    # five rows per table, except the two cycle tables which only hold three
    assert result.rows_read == 5 * 4 + 3 * 2
    engine = create_engine(target_url)
    try:
        with engine.connect() as conn:
            assert conn.execute(text("SELECT COUNT(*) FROM users")).scalar_one() == 5
            assert conn.execute(text("SELECT COUNT(*) FROM orders")).scalar_one() == 5
    finally:
        engine.dispose()


def test_only_and_exclude_select_tables(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    plan = make_engine_for(source_url, target_url, full_rules, key, only=["users"]).dry_run()
    assert [table.table for table in plan.tables] == ["users"]

    excluded = make_engine_for(
        source_url, target_url, full_rules, key, exclude=["orders"]
    ).dry_run()
    assert "orders" not in [table.table for table in excluded.tables]


def test_unknown_table_in_only(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    with pytest.raises(SchemaError, match="--tables"):
        make_engine_for(source_url, target_url, full_rules, key, only=["nope"]).dry_run()


def test_unknown_table_in_exclude(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    with pytest.raises(SchemaError, match="--exclude"):
        make_engine_for(source_url, target_url, full_rules, key, exclude=["nope"]).dry_run()


def test_exclude_can_leave_nothing_to_do(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    result = make_engine_for(
        source_url,
        target_url,
        full_rules,
        key,
        exclude=["users", "accounts", "orders", "employees", "cyc_a", "cyc_b"],
    ).run()
    assert result.rows_written == 0


def test_skip_and_truncate_actions(source_url: str, target_url: str, key: SecretKey) -> None:
    rules = load_rules_from_text(
        """
        tables:
          users: {action: copy, columns: {email: {transformer: email}}}
          accounts: {action: copy, columns: {user_id: {transformer: hash}}}
          orders: truncate
          employees: skip
        """
    )
    result = make_engine_for(source_url, target_url, rules, key).run()
    actions = {table.table: table.action for table in result.tables}
    assert actions["orders"] == "truncate"
    assert actions["employees"] == "skip"
    engine = create_engine(target_url)
    try:
        with engine.connect() as conn:
            # truncate keeps the table but not its rows
            assert conn.execute(text("SELECT COUNT(*) FROM orders")).scalar_one() == 0
            # skip leaves the table out of the target entirely
            assert "employees" not in inspect(engine).get_table_names()
    finally:
        engine.dispose()


def test_nulls_stay_null_by_default(source_url: str, target_url: str, key: SecretKey) -> None:
    rules = load_rules_from_text(
        """
        tables:
          orders:
            columns:
              note: {transformer: partial_mask, params: {keep_last: 4}}
        """
    )
    make_engine_for(source_url, target_url, rules, key).run()
    engine = create_engine(target_url)
    try:
        with engine.connect() as conn:
            nulls = conn.execute(
                text("SELECT COUNT(*) FROM orders WHERE note IS NULL")
            ).scalar_one()
        # every third order has no note in the fixture
        assert nulls > 0
    finally:
        engine.dispose()


def test_nulls_can_be_transformed(source_url: str, target_url: str, key: SecretKey) -> None:
    rules = load_rules_from_text(
        """
        settings: {null_passthrough: false}
        tables:
          users:
            columns:
              phone: {transformer: constant, params: {value: "unknown"}}
        """
    )
    make_engine_for(source_url, target_url, rules, key).run()
    engine = create_engine(target_url)
    try:
        with engine.connect() as conn:
            nulls = conn.execute(
                text("SELECT COUNT(*) FROM users WHERE phone IS NULL")
            ).scalar_one()
        assert nulls == 0
    finally:
        engine.dispose()


def test_the_source_is_untouched(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    source = create_engine(source_url)
    try:
        with source.connect() as conn:
            before = sorted(
                str(row) for row in conn.execute(text("SELECT * FROM users ORDER BY id"))
            )
    finally:
        source.dispose()

    make_engine_for(source_url, target_url, full_rules, key).run()

    source = create_engine(source_url)
    try:
        with source.connect() as conn:
            after = sorted(
                str(row) for row in conn.execute(text("SELECT * FROM users ORDER BY id"))
            )
    finally:
        source.dispose()
    assert before == after


def test_result_serialises_for_the_report(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    result = make_engine_for(source_url, target_url, full_rules, key).run()
    payload = result.to_dict()
    assert payload["totals"]["tables"] == 6
    assert payload["totals"]["rows_written"] == 89
    assert payload["source"] == source_url
    assert isinstance(payload["tables"][0]["masked"], dict)
    assert "unmasked" in payload["tables"][0]


def test_unmasked_columns_are_reported(source_url: str, target_url: str, key: SecretKey) -> None:
    rules = load_rules_from_text(
        """
        tables:
          users:
            columns:
              email: {transformer: email}
        """
    )
    result = make_engine_for(source_url, target_url, rules, key).run()
    assert "users.name" in result.unmasked_columns
    assert "users.email" not in result.unmasked_columns


# --------------------------------------------------------------------------- #
# Cyclic foreign keys
# --------------------------------------------------------------------------- #
def test_cyclic_tables_are_deferred_and_warned(
    source_url: str, target_url: str, key: SecretKey
) -> None:
    rules = load_rules_from_text(
        """
        tables:
          cyc_a: {columns: {id: {transformer: hash, namespace: cycle}}}
          cyc_b: {columns: {a_id: {transformer: hash, namespace: cycle}}}
        """
    )
    result = make_engine_for(source_url, target_url, rules, key).run()
    assert any(
        "deferred" in warning.lower() or "cycle" in warning.lower() for warning in result.warnings
    )
    engine = create_engine(target_url)
    try:
        with engine.connect() as conn:
            orphans = conn.execute(
                text(
                    "SELECT COUNT(*) FROM cyc_b b LEFT JOIN cyc_a a ON b.a_id = a.id "
                    "WHERE a.id IS NULL"
                )
            ).scalar_one()
        assert orphans == 0
    finally:
        engine.dispose()


def test_a_self_reference_is_warned_about(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    plan = make_engine_for(source_url, target_url, full_rules, key).dry_run()
    assert any("employees" in warning for warning in plan.warnings)


# --------------------------------------------------------------------------- #
# Dry run
# --------------------------------------------------------------------------- #
def test_dry_run_does_not_write(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    plan = make_engine_for(source_url, target_url, full_rules, key).dry_run()
    assert plan.samples
    assert plan.order
    assert not Path(target_url.replace("sqlite:///", "")).exists()


def test_dry_run_hides_the_original(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    plan = make_engine_for(source_url, target_url, full_rules, key).dry_run()
    shown = "\n".join(f"{sample.before} {sample.after}" for sample in plan.samples)
    assert "*" in shown
    assert "jane@example.com" not in shown


def test_dry_run_covers_every_table(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    plan = make_engine_for(source_url, target_url, full_rules, key).dry_run()
    assert {table.table for table in plan.tables} == {
        "users",
        "accounts",
        "orders",
        "employees",
        "cyc_a",
        "cyc_b",
    }


def test_dry_run_sample_rows_can_be_tuned(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    plan = make_engine_for(source_url, target_url, full_rules, key, sample_rows=1).dry_run()
    assert 0 < len(plan.samples) <= 22


# --------------------------------------------------------------------------- #
# Safety
# --------------------------------------------------------------------------- #
def test_same_database_is_refused(source_url: str, full_rules: RulesFile, key: SecretKey) -> None:
    with pytest.raises(SafetyError, match="same database"):
        make_engine_for(source_url, source_url, full_rules, key).run()


def test_a_non_empty_target_is_refused(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    make_engine_for(source_url, target_url, full_rules, key).run()
    with pytest.raises(SafetyError, match="not empty"):
        make_engine_for(source_url, target_url, full_rules, key).run()


def test_allow_non_empty_overwrites(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    make_engine_for(source_url, target_url, full_rules, key).run()
    result = make_engine_for(source_url, target_url, full_rules, key, allow_non_empty=True).run()
    assert result.rows_written == 89
    engine = create_engine(target_url)
    try:
        with engine.connect() as conn:
            assert conn.execute(text("SELECT COUNT(*) FROM users")).scalar_one() == 20
    finally:
        engine.dispose()


def test_a_target_with_other_tables_is_still_refused(
    source_url: str, tmp_path: Path, full_rules: RulesFile, key: SecretKey
) -> None:
    path = tmp_path / "occupied.sqlite"
    engine = create_engine(f"sqlite:///{path}")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE unrelated (id INTEGER)"))
    engine.dispose()
    with pytest.raises(SafetyError, match="not empty"):
        make_engine_for(source_url, f"sqlite:///{path}", full_rules, key).run()


def test_no_create_schema_is_refused_on_a_missing_target(
    source_url: str, tmp_path: Path, full_rules: RulesFile, key: SecretKey
) -> None:
    path = tmp_path / "bare.sqlite"
    path.touch()
    with pytest.raises(SafetyError, match="missing table"):
        make_engine_for(source_url, f"sqlite:///{path}", full_rules, key, create_schema=False).run()


def test_urls_are_redacted_in_the_result(
    source_url: str, target_url: str, full_rules: SecretKey, key: SecretKey
) -> None:
    result = make_engine_for(source_url, target_url, full_rules, key).run()  # type: ignore[arg-type]
    assert "***" not in result.source  # sqlite URLs carry no credentials


# --------------------------------------------------------------------------- #
# Schema creation
# --------------------------------------------------------------------------- #
def test_the_target_schema_mirrors_the_source(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    make_engine_for(source_url, target_url, full_rules, key).run()
    source_engine_ = create_engine(source_url)
    target = create_engine(target_url)
    try:
        source_columns = {
            column["name"]: str(column["type"])
            for column in inspect(source_engine_).get_columns("users")
        }
        target_columns = {
            column["name"]: str(column["type"]) for column in inspect(target).get_columns("users")
        }
        assert source_columns == target_columns
        source_fks = inspect(source_engine_).get_foreign_keys("orders")
        target_fks = inspect(target).get_foreign_keys("orders")
        assert len(source_fks) == len(target_fks) == 1
    finally:
        source_engine_.dispose()
        target.dispose()


def test_compile_plan_is_cached(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    masker_engine = MaskingEngine(
        source_url=source_url, target_url=target_url, rules=full_rules, key=key
    )
    connection = create_engine(source_url)
    try:
        masker_engine._resolve(connection)
        first = masker_engine._plan
        masker_engine._resolve(connection)
        assert masker_engine._plan is first
        assert masker_engine._schema is not None
    finally:
        connection.dispose()


def test_select_statement_orders_and_limits(
    source_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    from masker.engine import _select_statement

    engine = create_engine(source_url)
    try:
        schema = reflect_schema(engine)
        plan = compile_rules(full_rules, schema, key)
        compiled = plan.get("users")
        statement = _select_statement(compiled.table.table, compiled)
        assert "ORDER BY" in str(statement)
        assert "LIMIT" not in str(statement)  # no subset requested
    finally:
        engine.dispose()


def test_row_counts(engine: Engine) -> None:
    from masker.engine import _count_rows

    schema = reflect_schema(engine)
    assert _count_rows(engine, schema.get("users").table) == 20


def test_select_reads_only_the_columns_that_are_copied(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    from masker.engine import _select_statement

    engine = create_engine(source_url)
    try:
        schema = reflect_schema(engine)
        plan = compile_rules(full_rules, schema, key)
        statement = _select_statement(schema.get("users").table, plan.get("users"))
        assert "users.email" in str(statement.compile(engine))
    finally:
        engine.dispose()
    assert target_url.startswith("sqlite:///")


def test_engine_keeps_its_configuration(
    source_url: str, target_url: str, full_rules: RulesFile, key: SecretKey
) -> None:
    engine = make_engine_for(source_url, target_url, full_rules, key, batch_size=123)
    assert engine.options.batch_size == 123
    assert engine.options.create_schema
    assert not engine.options.allow_non_empty

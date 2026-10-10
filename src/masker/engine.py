"""The masking pipeline: read a batch, mask it, write it, repeat.

Design decisions worth knowing:

* the source is opened **read-only**;
* rows are streamed in batches (``--batch-size``) and written inside one
  transaction **per table**, so a failure rolls back that table cleanly;
* tables are processed in FK-dependency order, and tables that form an FK
  cycle are loaded inside a *single* transaction with foreign-key checks
  deferred;
* rows are read in primary-key order, which makes ``shuffle`` and ``subset``
  reproducible;
* the target is never touched in ``--dry-run``.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from sqlalchemy import Connection, Engine, Table, func, insert, inspect, select, text
from sqlalchemy import delete as sa_delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql import Select

from masker.config import (
    CompiledPlan,
    CompiledTable,
    RulesFile,
    assert_no_errors,
    compile_rules,
    validate_rules,
)
from masker.connect import (
    mask_value,
    redact_text,
    redact_url,
    require_different_databases,
    source_engine,
    target_engine,
    target_is_empty,
)
from masker.errors import MaskerError, SafetyError, SchemaError
from masker.keys import SecretKey
from masker.schema import ReflectedSchema, reflect_schema
from masker.transformers.base import BaseTransformer

__all__ = [
    "DryRunSample",
    "MaskingEngine",
    "ProgressSink",
    "RunOptions",
    "RunResult",
    "TableResult",
]


@dataclass(frozen=True, slots=True)
class RunOptions:
    """Everything the CLI can pass into a run."""

    batch_size: int = 5000
    only: list[str] | None = None
    exclude: list[str] | None = None
    subset_rows: int | None = None
    create_schema: bool = True
    allow_non_empty: bool = False
    sample_rows: int = 5
    enforce_fk: bool = True


class ProgressSink(Protocol):
    """Progress reporting, implemented by the CLI with Rich."""

    def table_started(self, name: str, total: int | None) -> None: ...

    def advance(self, rows: int) -> None: ...

    def table_done(self, name: str, rows: int, seconds: float) -> None: ...


@dataclass(slots=True)
class TableResult:
    """What happened to one table."""

    table: str
    action: str
    rows_read: int = 0
    rows_written: int = 0
    duration_s: float = 0.0
    masked: dict[str, str] = field(default_factory=dict)
    unmasked: list[str] = field(default_factory=list)
    unique_retries: int = 0
    deferred_constraints: bool = False


@dataclass(slots=True)
class RunResult:
    """The summary of a run, serialisable for ``masker report``."""

    started_at: datetime
    finished_at: datetime
    duration_s: float
    source: str
    target: str
    batch_size: int
    dry_run: bool
    tables: list[TableResult]
    warnings: list[str]
    created_schema: bool

    @property
    def rows_read(self) -> int:
        return sum(table.rows_read for table in self.tables)

    @property
    def rows_written(self) -> int:
        return sum(table.rows_written for table in self.tables)

    @property
    def masked_column_count(self) -> int:
        return sum(len(table.masked) for table in self.tables)

    @property
    def unmasked_columns(self) -> list[str]:
        return [f"{table.table}.{column}" for table in self.tables for column in table.unmasked]

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "duration_s": round(self.duration_s, 3),
            "source": self.source,
            "target": self.target,
            "batch_size": self.batch_size,
            "dry_run": self.dry_run,
            "created_schema": self.created_schema,
            "totals": {
                "tables": len(self.tables),
                "rows_read": self.rows_read,
                "rows_written": self.rows_written,
                "masked_columns": self.masked_column_count,
                "unmasked_columns": len(self.unmasked_columns),
            },
            "warnings": self.warnings,
            "tables": [
                {
                    "table": table.table,
                    "action": table.action,
                    "rows_read": table.rows_read,
                    "rows_written": table.rows_written,
                    "duration_s": round(table.duration_s, 3),
                    "masked": table.masked,
                    "unmasked": table.unmasked,
                    "unique_retries": table.unique_retries,
                    "deferred_constraints": table.deferred_constraints,
                }
                for table in self.tables
            ],
        }


@dataclass(frozen=True, slots=True)
class DryRunSample:
    """One before/after pair, with the original partially hidden."""

    table: str
    column: str
    transformer: str
    before: str
    after: str


@dataclass(frozen=True)
class DryRunPlan:
    tables: list[TableResult]
    samples: list[DryRunSample]
    order: list[list[str]]
    warnings: list[str]


class MaskingEngine:
    """Copies and masks a source database into a target database."""

    def __init__(
        self,
        *,
        source_url: str,
        target_url: str,
        rules: RulesFile,
        key: SecretKey,
        options: RunOptions | None = None,
        progress: ProgressSink | None = None,
    ) -> None:
        self.source_url = source_url
        self.target_url = target_url
        self.rules = rules
        self.key = key
        self.options = options or RunOptions()
        self.progress = progress
        self.warnings: list[str] = []
        self._schema: ReflectedSchema | None = None
        self._plan: CompiledPlan | None = None

    # ------------------------------------------------------------------ #
    # Preparation
    # ------------------------------------------------------------------ #
    def _resolve(self, engine: Engine) -> tuple[ReflectedSchema, CompiledPlan]:
        if self._schema is None:
            self._schema = reflect_schema(engine)
        if self._plan is None:
            selected = self._selected_tables(self._schema)
            issues = validate_rules(self.rules, self._schema)
            assert_no_errors(issues)
            self.warnings.extend(issue.message for issue in issues if issue.severity == "warning")
            if self.options.subset_rows is not None:
                # A row cap given to the engine applies to every copied table,
                # whether or not the rules file declared action: subset.
                self.rules.settings = self.rules.settings.model_copy(
                    update={"subset_rows": self.options.subset_rows}
                )
            self._plan = compile_rules(self.rules, self._schema, self.key, only=selected)
            self.warnings.extend(_cycle_warnings(self._schema, self._plan))
        return self._schema, self._plan

    def _selected_tables(self, schema: ReflectedSchema) -> list[str]:
        names = set(schema.tables)
        if self.options.only:
            unknown = sorted(set(self.options.only) - names)
            if unknown:
                raise SchemaError(
                    f"Unknown table(s) in --tables: {', '.join(unknown)}",
                    hint=f"Reflected tables: {', '.join(sorted(names)) or '<none>'}",
                )
            names &= set(self.options.only)
        if self.options.exclude:
            unknown = sorted(set(self.options.exclude) - names)
            if unknown:
                raise SchemaError(
                    f"Unknown table(s) in --exclude: {', '.join(unknown)}",
                    hint=f"Reflected tables: {', '.join(sorted(names)) or '<none>'}",
                )
            names -= set(self.options.exclude)
        return sorted(names)

    # ------------------------------------------------------------------ #
    # Dry run
    # ------------------------------------------------------------------ #
    def dry_run(self) -> DryRunPlan:
        """Build the plan and a masked sample without touching the target."""
        with source_engine(self.source_url) as source:
            schema, plan = self._resolve(source)
            results: list[TableResult] = []
            samples: list[DryRunSample] = []

            for group in plan.order:
                for name in group:
                    if name not in plan.tables:
                        continue
                    compiled = plan.tables[name]
                    results.append(
                        TableResult(
                            table=name,
                            action=compiled.action,
                            masked={
                                column: transformer.describe()
                                for column, transformer in compiled.masked_columns.items()
                            },
                            unmasked=compiled.unmasked_columns,
                            deferred_constraints=_needs_deferred(group, schema),
                        )
                    )
                    if not compiled.copies_rows:
                        continue
                    samples.extend(self._sample(source, schema, compiled))
        return DryRunPlan(
            tables=results,
            samples=samples,
            order=plan.order,
            warnings=list(self.warnings),
        )

    def _sample(
        self,
        source: Engine,
        schema: ReflectedSchema,
        compiled: CompiledTable,
    ) -> list[DryRunSample]:
        masked = compiled.masked_columns
        if not masked or self.options.sample_rows <= 0:
            return []
        # Fresh transformers: a dry run must not disturb the real one.
        preview_plan = compile_rules(self.rules, schema, self.key, only=[compiled.name])
        preview_compiled = preview_plan.tables[compiled.name]
        preview_transformers = preview_compiled.masked_columns
        # Two-pass transformers (shuffle) need the same preparation as a run.
        self._prepare_transformers(source, preview_compiled, preview_transformers)

        table = compiled.table.table
        statement = select(*[table.c[name] for name in masked]).limit(self.options.sample_rows)
        samples: list[DryRunSample] = []
        with source.connect() as conn:
            for row in conn.execute(statement):
                for index, name in enumerate(masked):
                    original = row[index]
                    masked_value = preview_transformers[name](original)
                    samples.append(
                        DryRunSample(
                            table=compiled.name,
                            column=name,
                            transformer=preview_transformers[name].describe(),
                            before=mask_value(original),
                            after=mask_value(masked_value),
                        )
                    )
        return samples

    # ------------------------------------------------------------------ #
    # Run
    # ------------------------------------------------------------------ #
    def run(self) -> RunResult:
        """Copy the schema and masked data into the target."""
        require_different_databases(self.source_url, self.target_url)
        started = datetime.now(timezone.utc)
        tick = time.monotonic()
        results: list[TableResult] = []
        created_schema = False

        with source_engine(self.source_url) as source:
            schema, plan = self._resolve(source)

            with target_engine(self.target_url) as target:
                if not self.options.allow_non_empty and not target_is_empty(target):
                    raise SafetyError(
                        f"The target database is not empty: {redact_url(target.url)}",
                        hint=(
                            "Masker refuses to write into a database that already holds data. "
                            "Use an empty database, or pass --allow-non-empty if you are sure."
                        ),
                    )
                if target.dialect.name in ("mysql", "mariadb") and any(
                    _needs_deferred(group, schema) and any(n in plan.tables for n in group)
                    for group in plan.order
                ):
                    raise SafetyError("MySQL cannot defer cyclic foreign-key checks safely.")
                if self.options.create_schema:
                    created_schema = _create_schema(target, schema, plan)
                else:
                    _require_existing_tables(target, schema, plan)
                if self.options.allow_non_empty:
                    # Masked values are deterministic, so re-running into a
                    # populated target would collide with the rows already
                    # there. Clear the tables we are about to write, children
                    # first, so a refresh is idempotent.
                    _clear_in_scope_tables(target, schema, plan)

                for group in plan.order:
                    group_tables = [name for name in group if name in plan.tables]
                    if not group_tables:
                        continue
                    results.extend(
                        self._copy_group(source, target, schema, plan, group, group_tables)
                    )

        return RunResult(
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            duration_s=time.monotonic() - tick,
            source=redact_url(self.source_url),
            target=redact_url(self.target_url),
            batch_size=self.options.batch_size,
            dry_run=False,
            tables=results,
            warnings=list(self.warnings),
            created_schema=created_schema,
        )

    def _copy_group(
        self,
        source: Engine,
        target: Engine,
        schema: ReflectedSchema,
        plan: CompiledPlan,
        group: list[str],
        group_tables: list[str],
    ) -> list[TableResult]:
        """Copy one dependency group; a multi-table group shares a transaction."""
        deferred = _needs_deferred(group, schema)
        results: list[TableResult] = []
        with target.begin() as conn:
            if deferred:
                _defer_constraints(conn)
            for name in group_tables:
                compiled = plan.tables[name]
                if not compiled.copies_rows:
                    results.append(
                        TableResult(
                            table=name,
                            action=compiled.action,
                            unmasked=compiled.unmasked_columns,
                            deferred_constraints=deferred,
                        )
                    )
                    continue
                results.append(self._copy_table(source, conn, compiled, deferred=deferred))
        return results

    def _copy_table(
        self,
        source: Engine,
        target_conn: Connection,
        compiled: CompiledTable,
        *,
        deferred: bool,
    ) -> TableResult:
        started = time.monotonic()
        table = compiled.table.table
        masked = compiled.masked_columns
        column_names = compiled.table.column_names

        self._prepare_transformers(source, compiled, masked)

        total = _count_rows(source, table) if self.progress else None
        if self.progress:
            self.progress.table_started(compiled.name, total)

        statement = _select_statement(table, compiled)
        insert_statement = insert(table)
        rows_read = 0
        rows_written = 0

        try:
            with source.connect() as source_conn:
                streamed = source_conn.execution_options(stream_results=True).execute(statement)
                for partition in streamed.partitions(self.options.batch_size):
                    batch = [self._mask_row(row, column_names, masked) for row in partition]
                    rows_read += len(batch)
                    if batch:
                        target_conn.execute(insert_statement, batch)
                        rows_written += len(batch)
                    if self.progress:
                        self.progress.advance(len(batch))
        except SQLAlchemyError as exc:
            raise MaskerError(
                f"Failed while copying {compiled.name}: {type(exc).__name__}. "
                "Database details are hidden because they can contain row values.",
                hint="The transaction for this table was rolled back.",
            ) from exc

        retries = sum(
            transformer.retries
            for transformer in masked.values()
            if hasattr(transformer, "retries")
        )
        result = TableResult(
            table=compiled.name,
            action=compiled.action,
            rows_read=rows_read,
            rows_written=rows_written,
            duration_s=time.monotonic() - started,
            masked={column: transformer.describe() for column, transformer in masked.items()},
            unmasked=compiled.unmasked_columns,
            unique_retries=retries,
            deferred_constraints=deferred,
        )
        if self.progress:
            self.progress.table_done(compiled.name, rows_written, result.duration_s)
        return result

    def _prepare_transformers(
        self,
        source: Engine,
        compiled: CompiledTable,
        masked: dict[str, BaseTransformer[Any]],
    ) -> None:
        """Run the pre-pass for transformers that need the whole column first."""
        needing = [
            (name, transformer)
            for name, transformer in masked.items()
            if transformer.requires_prepass
        ]
        if not needing:
            return
        table = compiled.table.table
        with source.connect() as conn:
            for name, transformer in needing:
                statement = (
                    select(table.c[name])
                    .where(table.c[name].is_not(None))
                    .distinct()
                    .order_by(table.c[name])
                )
                values = [row[0] for row in conn.execute(statement)]
                transformer.prepare(values)

    def _mask_row(
        self,
        row: Sequence[Any],
        column_names: list[str],
        masked: dict[str, BaseTransformer[Any]],
    ) -> dict[str, Any]:
        record = dict(zip(column_names, row, strict=True))
        for name, transformer in masked.items():
            record[name] = transformer(record[name])
        return record


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _select_statement(table: Table, compiled: CompiledTable) -> Select[Any]:
    columns = [table.c[name] for name in compiled.table.column_names]
    statement = select(*columns).select_from(table)
    order_by = compiled.order_by or compiled.table.primary_key
    if order_by:
        statement = statement.order_by(*[table.c[name] for name in order_by])
    if compiled.subset_rows:
        # Applied for any action that copies rows: `--subset-rows` on the
        # command line is a global cap, not only a property of action: subset.
        statement = statement.limit(compiled.subset_rows)
    return statement


def _require_existing_tables(target: Engine, schema: ReflectedSchema, plan: CompiledPlan) -> None:
    """Refuse to run with ``--no-create-schema`` when tables are missing.

    Without this the failure surfaces later as a driver-level "no such table",
    which does not say what to do about it.
    """
    existing = set(inspect(target).get_table_names())
    missing = sorted(
        name
        for name, compiled in plan.tables.items()
        if compiled.action != "skip" and name not in existing
    )
    if missing:
        raise SafetyError(
            f"The target database is missing table(s): {', '.join(missing)}",
            hint=(
                "Let Masker create them (drop --no-create-schema), or create them yourself "
                "with the same shape as the source."
            ),
        )


def _clear_in_scope_tables(target: Engine, schema: ReflectedSchema, plan: CompiledPlan) -> None:
    """Delete existing rows from the tables this run is about to write.

    Used by ``--allow-non-empty``. Children are cleared before parents so the
    deletes never violate a foreign key, and only tables that actually exist in
    the target are touched.
    """
    existing = set(inspect(target).get_table_names())
    with target.begin() as conn:
        for group in reversed(plan.order):
            if _needs_deferred(group, schema):
                _defer_constraints(conn)
            for name in reversed(
                [
                    n
                    for n in group
                    if n in plan.tables and n in existing and plan.tables[n].action != "skip"
                ]
            ):
                conn.execute(sa_delete(schema.tables[name].table))


def _count_rows(engine: Engine, table: Table) -> int:
    with engine.connect() as conn:
        return int(conn.execute(select(func.count()).select_from(table)).scalar_one())


def _needs_deferred(group: list[str], schema: ReflectedSchema) -> bool:
    """True when this group's rows cannot satisfy FK checks row by row."""
    if len(group) > 1:
        return True
    table = schema.tables.get(group[0])
    return table is not None and group[0] in table.referenced_tables


def _defer_constraints(conn: Connection) -> None:
    """Defer foreign-key checks for the rest of this transaction."""
    dialect = conn.engine.dialect.name
    if dialect == "sqlite":
        conn.execute(text("PRAGMA defer_foreign_keys = ON"))
    elif dialect == "postgresql":
        conn.execute(text("SET CONSTRAINTS ALL DEFERRED"))
    elif dialect in ("mysql", "mariadb"):
        raise SafetyError(
            "MySQL cannot defer cyclic foreign-key checks safely.",
            hint="Remove the cycle or use a backend with deferred constraints.",
        )


def _cycle_warnings(schema: ReflectedSchema, plan: CompiledPlan) -> list[str]:
    warnings: list[str] = []
    for group in schema.cycles:
        if not any(name in plan.tables for name in group):
            continue
        if len(group) > 1:
            warnings.append(
                f"FK cycle: {', '.join(group)} are copied in one transaction with "
                "foreign-key checks deferred."
            )
        else:
            warnings.append(
                f"{group[0]} has a self-referencing foreign key; its rows are copied "
                "with foreign-key checks deferred."
            )
    return warnings


def _create_schema(target: Engine, schema: ReflectedSchema, plan: CompiledPlan) -> bool:
    """Create the tables that will be written, in FK order.

    The reflected metadata is reused as-is: ``Table`` objects are not bound to
    an engine, so they describe the source schema and can create the same
    shape on the target. Cross-dialect copies (say SQLite to PostgreSQL) are
    best-effort -- prefer copying between the same backend.
    """
    wanted: list[Table] = []
    for group in plan.order:
        for name in group:
            compiled = plan.tables.get(name)
            if compiled is None or compiled.action == "skip":
                continue
            wanted.append(schema.tables[name].table)
    if not wanted:
        return False

    _mark_cycle_constraints(schema, plan, target)
    try:
        schema.metadata.create_all(bind=target, tables=wanted, checkfirst=True)
    except SQLAlchemyError as exc:
        raise SchemaError(f"Could not create the target schema: {redact_text(str(exc))}") from exc
    return True


def _mark_cycle_constraints(
    schema: ReflectedSchema,
    plan: CompiledPlan,
    target: Engine,
) -> None:
    """Mark FK constraints that close a cycle so their DDL is emitted last.

    ``use_alter`` is SQLAlchemy's documented way to create circular foreign
    keys: the constraint is added with ``ALTER TABLE`` once every table
    exists. On PostgreSQL the constraint is also made
    ``DEFERRABLE INITIALLY DEFERRED``, which is what allows a cycle to be
    loaded inside a single transaction.
    """
    dialect = target.dialect.name
    if dialect == "sqlite":
        return  # SQLite accepts forward references in CREATE TABLE

    cyclic: set[str] = set()
    for group in plan.order:
        if _needs_deferred(group, schema):
            cyclic.update(group)
    if not cyclic:
        return

    for table_name in cyclic:
        table = schema.metadata.tables.get(table_name)
        if table is None:
            continue
        for constraint in list(table.foreign_key_constraints):
            if not any(element.column.table.name in cyclic for element in constraint.elements):
                continue
            constraint.use_alter = True
            if not isinstance(constraint.name, str):
                columns = "_".join(column.name for column in constraint.columns)
                constraint.name = f"masker_fk_{table_name}_{columns}"
            if dialect == "postgresql":
                constraint.deferrable = True
                constraint.initially = "DEFERRED"

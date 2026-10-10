"""Leak verification for an anonymized target.

``masker verify`` answers one question with evidence: does any original value
of a masked column still appear in the target? It samples distinct values from
the source and looks for them in the target with a chunked ``IN`` query, so it
costs a few indexed round-trips rather than a full scan of both databases.

It also checks referential integrity of the target, because a masked dump with
orphaned foreign keys is broken in a way that is easy to miss.

A clean verify is a good sign, not a proof: it covers the columns it sampled,
not re-identification by combination. See ``README.md`` → Limitations.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Table, and_, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from masker.config import (
    PASSTHROUGH_TRANSFORMERS,
    CompiledTable,
    RulesFile,
    compile_rules,
)
from masker.connect import mask_value, redact_text, redact_url, source_engine
from masker.errors import MaskerError, SchemaError
from masker.keys import SecretKey
from masker.scan import NON_GATING_CATEGORIES, match_name, scan_schema
from masker.schema import ReflectedSchema, TableInfo, reflect_schema, row_count

__all__ = [
    "ColumnCheck",
    "OrphanCheck",
    "UnruledCheck",
    "VerifyResult",
    "verify",
]

#: Values per ``IN (...)`` query. Kept well under every driver's parameter limit.
CHUNK_SIZE = 400
#: Distinct target values fetched for a column before giving up on set matching.
MAX_TARGET_VALUES = 200_000


#: Above this share of samples matching, a domain-preserving transformer is
#: treated as not having changed anything at all, which is a real failure.
COLLISION_FAILURE_RATE = 0.5


@dataclass(frozen=True, slots=True)
class ColumnCheck:
    """The result of looking for one masked column's originals in the target."""

    table: str
    column: str
    transformer: str
    sampled: int
    leaked: int
    examples: tuple[str, ...] = ()
    #: ``True`` for ``date_shift``/``number_noise``, where a masked value can
    #: legitimately coincide with another row's original.
    preserves_domain: bool = False

    @property
    def label(self) -> str:
        return f"{self.table}.{self.column}"

    @property
    def rate(self) -> float:
        return self.leaked / self.sampled if self.sampled else 0.0

    @property
    def severity(self) -> str:
        """``error`` for a genuine leak, ``warn`` for an expected coincidence.

        A jitter or shift transformer stays inside the original value's domain,
        so with a few hundred rows some outputs land on other rows' originals.
        That is a coincidence, not a leak -- unless almost every value matches,
        which means the transformer changed nothing.
        """
        if not self.leaked:
            return "ok"
        if self.preserves_domain and self.rate < COLLISION_FAILURE_RATE:
            return "warn"
        return "error"

    @property
    def ok(self) -> bool:
        return self.severity != "error"


@dataclass(frozen=True, slots=True)
class UnruledCheck:
    """A column with no masking rule, copied into the target verbatim.

    This is the check that catches a *missing* rule rather than a broken one:
    without it, deleting a rule from the file would make ``verify`` report
    success while shipping the original values.
    """

    table: str
    column: str
    rows: int
    suspected_pii: bool
    category: str | None = None
    #: ``True`` when the rules file says ``transformer: keep`` -- a reviewed
    #: decision rather than an omission.
    explicit: bool = False

    @property
    def label(self) -> str:
        return f"{self.table}.{self.column}"

    @property
    def severity(self) -> str:
        if self.suspected_pii and not self.explicit:
            return "error"
        return "warn"


@dataclass(frozen=True, slots=True)
class OrphanCheck:
    """Rows whose foreign key points at nothing in the target."""

    table: str
    column: str
    referred_table: str
    referred_column: str
    orphans: int

    @property
    def label(self) -> str:
        return f"{self.table}.{self.column} -> {self.referred_table}.{self.referred_column}"

    @property
    def ok(self) -> bool:
        return self.orphans == 0


@dataclass(frozen=True)
class VerifyResult:
    checks: tuple[ColumnCheck, ...]
    orphans: tuple[OrphanCheck, ...]
    unruled: tuple[UnruledCheck, ...]
    source: str
    target: str

    @property
    def leaks(self) -> tuple[ColumnCheck, ...]:
        """Columns where an original value is still present and that is a real leak."""
        return tuple(check for check in self.checks if check.severity == "error")

    @property
    def coincidences(self) -> tuple[ColumnCheck, ...]:
        """Domain-preserving columns with an expected collision rate."""
        return tuple(check for check in self.checks if check.severity == "warn")

    @property
    def broken_fks(self) -> tuple[OrphanCheck, ...]:
        return tuple(check for check in self.orphans if not check.ok)

    @property
    def total_leaked(self) -> int:
        return sum(check.leaked for check in self.leaks)

    @property
    def unmasked_pii(self) -> tuple[UnruledCheck, ...]:
        """Columns with no rule that the heuristics think hold personal data.

        Filters on severity rather than on ``suspected_pii`` alone: a column the
        rules file explicitly sets to ``keep`` is a reviewed decision, so it is
        reported but does not fail the run. This mirrors :attr:`leaks`, and
        keeps ``verify`` in step with ``scan --strict``.
        """
        return tuple(check for check in self.unruled if check.severity == "error")

    @property
    def ok(self) -> bool:
        return not self.leaks and not self.broken_fks and not self.unmasked_pii

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "ok": self.ok,
            "total_leaked_values": self.total_leaked,
            "columns_checked": len(self.checks),
            "leaks": [
                {
                    "table": check.table,
                    "column": check.column,
                    "transformer": check.transformer,
                    "sampled": check.sampled,
                    "leaked": check.leaked,
                    "examples": list(check.examples),
                }
                for check in self.leaks
            ],
            "expected_coincidences": [
                {
                    "table": check.table,
                    "column": check.column,
                    "transformer": check.transformer,
                    "sampled": check.sampled,
                    "leaked": check.leaked,
                    "rate": round(check.rate, 4),
                }
                for check in self.coincidences
            ],
            "unruled_columns": [
                {
                    "table": check.table,
                    "column": check.column,
                    "rows": check.rows,
                    "suspected_pii": check.suspected_pii,
                    "category": check.category,
                }
                for check in self.unruled
            ],
            "broken_foreign_keys": [
                {
                    "table": check.table,
                    "column": check.column,
                    "referred_table": check.referred_table,
                    "referred_column": check.referred_column,
                    "orphans": check.orphans,
                }
                for check in self.broken_fks
            ],
        }


def verify(
    *,
    source_url: str,
    target_url: str,
    rules: RulesFile,
    key: SecretKey,
    sample_size: int = 500,
    check_fk: bool = True,
    tables: list[str] | None = None,
) -> VerifyResult:
    """Check the target for original values and orphaned foreign keys."""
    checks: list[ColumnCheck] = []
    orphans: list[OrphanCheck] = []
    unruled: list[UnruledCheck] = []

    with source_engine(source_url) as source, source_engine(target_url) as target:
        source_schema = reflect_schema(source)
        target_schema = reflect_schema(target)
        plan = compile_rules(rules, source_schema, key, only=tables)

        for name, compiled in plan.tables.items():
            if not compiled.copies_rows:
                continue
            source_table = compiled.table.table
            target_table = target_schema.tables.get(name)
            if target_table is None:
                raise SchemaError(f"The target is missing copied table {name!r}.")
            missing = sorted(set(compiled.table.column_names) - set(target_table.column_names))
            if missing:
                raise SchemaError(
                    f"The target table {name!r} is missing columns: {', '.join(missing)}"
                )
            for column, transformer in compiled.masked_columns.items():
                if transformer.name in PASSTHROUGH_TRANSFORMERS:
                    continue
                checks.append(
                    _check_column(
                        source,
                        target,
                        source_table,
                        target_table.table,
                        column,
                        transformer.describe(),
                        sample_size,
                        preserves_domain=transformer.preserves_domain,
                    )
                )

        for name, compiled in plan.tables.items():
            if not compiled.copies_rows or name not in target_schema.tables:
                continue
            unruled.extend(_check_unruled(target, compiled, target_schema.tables[name]))

        if check_fk:
            orphans.extend(_check_foreign_keys(target, target_schema))

    return VerifyResult(
        checks=tuple(checks),
        orphans=tuple(orphans),
        unruled=tuple(unruled),
        source=redact_url(source_url),
        target=redact_url(target_url),
    )


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #
def _check_column(
    source: Engine,
    target: Engine,
    source_table: Table,
    target_table: Table,
    column: str,
    transformer: str,
    sample_size: int,
    *,
    preserves_domain: bool = False,
) -> ColumnCheck:
    """Look for a sample of the source's distinct values inside the target."""
    column_object = source_table.c[column]
    statement = (
        select(column_object).where(column_object.is_not(None)).distinct().limit(sample_size)
    )
    try:
        with source.connect() as conn:
            originals = [row[0] for row in conn.execute(statement)]
    except SQLAlchemyError as exc:
        raise SchemaError(f"Could not sample {source_table.name}.{column}: {exc}") from exc

    if not originals:
        return ColumnCheck(source_table.name, column, transformer, 0, 0, (), preserves_domain)

    leaked: list[Any] = []
    try:
        with target.connect() as conn:
            target_column = target_table.c[column]
            for chunk in _chunks(originals, CHUNK_SIZE):
                found = conn.execute(
                    select(target_column)
                    .where(target_column.in_(chunk))
                    .distinct()
                    .limit(len(chunk))
                ).scalars()
                leaked.extend(found)
    except SQLAlchemyError as exc:
        raise MaskerError(
            f"Could not verify {target_table.name}.{column}: {redact_text(str(exc))}"
        ) from exc

    return ColumnCheck(
        table=source_table.name,
        column=column,
        transformer=transformer,
        sampled=len(originals),
        leaked=len(leaked),
        examples=tuple(mask_value(value) for value in leaked[:5]),
        preserves_domain=preserves_domain,
    )


def _check_unruled(
    target: Engine, compiled: CompiledTable, target_table: TableInfo
) -> list[UnruledCheck]:
    """List the columns of a copied table that have no masking rule."""
    unruled_names = compiled.unmasked_columns
    if not unruled_names:
        return []
    rows = row_count(target, target_table.table)
    out: list[UnruledCheck] = []
    findings = {
        finding.column: finding
        for finding in scan_schema(
            target, ReflectedSchema({compiled.name: target_table}, target_table.table.metadata)
        ).findings
    }
    for name in unruled_names:
        pattern = match_name(name)
        finding = findings.get(name)
        gating = (
            pattern is not None
            and pattern.category not in NON_GATING_CATEGORIES
            and pattern.confidence in ("high", "medium")
        )
        out.append(
            UnruledCheck(
                table=compiled.name,
                column=name,
                rows=rows,
                suspected_pii=gating
                or (
                    finding is not None
                    and finding.category not in NON_GATING_CATEGORIES
                    and finding.confidence in ("high", "medium")
                ),
                category=finding.category if finding else (pattern.category if pattern else None),
                explicit=compiled.columns[name].transformer is not None,
            )
        )
    return out


def _check_foreign_keys(target: Engine, schema: ReflectedSchema) -> list[OrphanCheck]:
    """Count rows in the target whose foreign key matches nothing."""
    results: list[OrphanCheck] = []
    for table_name, table in sorted(schema.tables.items()):
        for fk in table.foreign_keys:
            if fk.referred_table not in schema.tables:
                continue
            child = table.table
            # Alias the parent: a self-referencing FK joins a table to itself
            # and would otherwise produce ambiguous column names.
            parent = schema.tables[fk.referred_table].table.alias("masker_parent")
            conditions = [
                child.c[child_column] == parent.c[parent_column]
                for child_column, parent_column in zip(fk.columns, fk.referred_columns, strict=True)
            ]
            first_parent = parent.c[fk.referred_columns[0]]
            statement = (
                select(func.count())
                .select_from(child.outerjoin(parent, and_(*conditions)))
                .where(
                    first_parent.is_(None),
                    *[child.c[column].is_not(None) for column in fk.columns],
                )
            )
            try:
                with target.connect() as conn:
                    count = int(conn.execute(statement).scalar_one())
            except SQLAlchemyError as exc:
                raise MaskerError(
                    f"Could not check {table_name}.{fk.columns[0]}: {redact_text(str(exc))}"
                ) from exc
            results.append(
                OrphanCheck(
                    table=table_name,
                    column=",".join(fk.columns),
                    referred_table=fk.referred_table,
                    referred_column=",".join(fk.referred_columns),
                    orphans=count,
                )
            )
    return results


def _chunks(items: Sequence[Any], size: int) -> list[Sequence[Any]]:
    return [items[start : start + size] for start in range(0, len(items), size)]

"""The rules file (``masker.yaml``): models, loading, validation, compilation.

A rules file is deliberately small and reviewable::

    version: 1
    settings:
      batch_size: 5000
    tables:
      users:
        action: copy
        columns:
          email: {transformer: email}
          full_name: {transformer: fake, params: {provider: name}}
      audit_log: {action: skip}

Anything the file does not mention is copied verbatim, and ``masker scan`` /
``masker report`` list those columns so omissions are visible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from masker.errors import ConfigError
from masker.keys import SecretKey
from masker.schema import ReflectedSchema, TableInfo
from masker.transformers.base import BaseTransformer, ColumnContext
from masker.transformers.registry import REGISTRY
from masker.values import sql_kind

__all__ = [
    "CompiledColumn",
    "CompiledPlan",
    "CompiledTable",
    "Issue",
    "RulesFile",
    "Settings",
    "TableRule",
    "TransformerRule",
    "assert_no_errors",
    "compile_rules",
    "load_rules",
    "load_rules_from_text",
    "validate_rules",
]

TableAction = Literal["copy", "skip", "truncate", "subset"]
Severity = Literal["error", "warning", "info"]

#: Transformers that copy the original value through, i.e. leave it unmasked.
PASSTHROUGH_TRANSFORMERS = frozenset({"keep"})

_STRING_KINDS = frozenset({"string", "unknown"})
_NUMERIC_KINDS = frozenset({"integer", "numeric", "float"})
_DATE_KINDS = frozenset({"date", "datetime"})

#: Transformers whose output is text and cannot be stored in a numeric column.
_TEXT_ONLY_TRANSFORMERS = frozenset({"email", "partial_mask", "preserve_format", "regex_replace"})


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #
class TransformerRule(BaseModel):
    """One column's masking rule."""

    model_config = ConfigDict(extra="forbid")

    transformer: str
    params: dict[str, Any] = Field(default_factory=dict)
    #: Digest namespace. Columns joined by a foreign key already share one
    #: automatically; set this to link columns the schema does not relate
    #: (for example an email copied into a log table).
    namespace: str | None = None
    #: Force uniqueness handling on/off. Defaults to what the schema says.
    unique: bool | None = None
    #: ``keep`` (default) leaves NULLs alone; ``transform`` passes them through.
    on_null: Literal["keep", "transform"] | None = None


class TableRule(BaseModel):
    """What to do with one table."""

    model_config = ConfigDict(extra="forbid")

    action: TableAction = "copy"
    subset_rows: int | None = Field(default=None, ge=1)
    order_by: list[str] = Field(default_factory=list)
    columns: dict[str, TransformerRule] = Field(default_factory=dict)


class Settings(BaseModel):
    """Global knobs. Everything here has a safe default."""

    model_config = ConfigDict(extra="forbid")

    batch_size: int = Field(default=5000, ge=1)
    null_passthrough: bool = True
    create_schema: bool = True
    subset_rows: int | None = Field(default=None, ge=1)
    locale: str | None = None
    unique_max_attempts: int = Field(default=1000, ge=1)
    #: Rows sniffed by ``masker scan`` per column.
    sample_size: int = Field(default=200, ge=1)
    #: Distinct values per column checked by ``masker verify``.
    verify_sample_size: int = Field(default=500, ge=1)


class RulesFile(BaseModel):
    """The whole ``masker.yaml``."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    settings: Settings = Field(default_factory=Settings)
    tables: dict[str, TableRule] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def load_rules(path: str | Path) -> RulesFile:
    rules_path = Path(path)
    if not rules_path.is_file():
        raise ConfigError(
            f"Rules file not found: {rules_path}",
            hint="Generate one with: masker init --source <url>",
        )
    try:
        text = rules_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Could not read {rules_path}: {exc}") from exc
    return load_rules_from_text(text, source=str(rules_path))


def load_rules_from_text(text: str, *, source: str = "<rules>") -> RulesFile:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{source} is not valid YAML: {exc}") from exc

    if raw is None:
        raise ConfigError(f"{source} is empty.", hint="Run: masker init --source <url>")
    if not isinstance(raw, dict):
        raise ConfigError(f"{source} must be a mapping at the top level, got {type(raw).__name__}.")

    try:
        return RulesFile.model_validate(_normalise(raw))
    except ValidationError as exc:
        raise ConfigError(
            f"{source} is not a valid rules file:\n{format_validation_error(exc)}"
        ) from exc


def format_validation_error(exc: ValidationError) -> str:
    lines = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "<root>"
        lines.append(f"  - {location}: {error['msg']}")
    return "\n".join(lines)


def _normalise(raw: dict[str, Any]) -> dict[str, Any]:
    """Accept the shorthands: ``email: email`` and ``audit_log: skip``."""
    tables = raw.get("tables")
    if isinstance(tables, dict):
        normalised: dict[str, Any] = {}
        for table_name, table_rule in tables.items():
            if isinstance(table_rule, str):
                table_rule = {"action": table_rule}
            if isinstance(table_rule, dict):
                columns = table_rule.get("columns")
                if isinstance(columns, dict):
                    table_rule = {
                        **table_rule,
                        "columns": {
                            name: _normalise_column(name, rule) for name, rule in columns.items()
                        },
                    }
            normalised[table_name] = table_rule
        raw = {**raw, "tables": normalised}
    return raw


def _normalise_column(name: str, rule: Any) -> Any:
    if rule is None or isinstance(rule, str):
        return {"transformer": "keep" if rule is None else rule}
    return rule


# --------------------------------------------------------------------------- #
# Issues
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class Issue:
    """One finding from :func:`validate_rules`."""

    severity: Severity
    code: str
    message: str
    table: str | None = None
    column: str | None = None
    hint: str | None = None

    @property
    def where(self) -> str:
        if self.table and self.column:
            return f"{self.table}.{self.column}"
        return self.table or "<rules>"


def assert_no_errors(issues: list[Issue]) -> None:
    """Raise :class:`ConfigError` if any issue is an error."""
    errors = [issue for issue in issues if issue.severity == "error"]
    if not errors:
        return
    rendered = "\n".join(f"  - {issue.where}: {issue.message}" for issue in errors)
    first_hint = next((issue.hint for issue in errors if issue.hint), None)
    raise ConfigError(
        f"{len(errors)} problem(s) in the rules file:\n{rendered}",
        hint=first_hint,
    )


# --------------------------------------------------------------------------- #
# Static validation
# --------------------------------------------------------------------------- #
def validate_rules(rules: RulesFile, schema: ReflectedSchema) -> list[Issue]:
    """Check the rules against the reflected schema.

    Returns every finding (errors, warnings and informational notes). Use
    :func:`assert_no_errors` to turn errors into an exception.
    """
    issues: list[Issue] = []

    for table_name, table_rule in rules.tables.items():
        table = schema.tables.get(table_name)
        if table is None:
            issues.append(
                Issue(
                    "error",
                    "unknown-table",
                    f"Unknown table {table_name!r}.",
                    table=table_name,
                    hint=f"Reflected tables: {', '.join(sorted(schema.tables)) or '<none>'}",
                )
            )
            continue

        if (
            table_rule.action == "subset"
            and table_rule.subset_rows is None
            and rules.settings.subset_rows is None
        ):
            issues.append(
                Issue(
                    "warning",
                    "subset-without-rows",
                    "action: subset needs subset_rows (or --subset-rows).",
                    table=table_name,
                )
            )
        if table_rule.action in ("skip", "truncate"):
            issues.append(
                Issue(
                    "info",
                    "table-not-copied",
                    f"action: {table_rule.action} -- no rows will be copied.",
                    table=table_name,
                )
            )
        for order_column in table_rule.order_by:
            if table.column(order_column) is None:
                issues.append(
                    Issue(
                        "error",
                        "unknown-order-by",
                        f"order_by column {order_column!r} does not exist.",
                        table=table_name,
                        column=order_column,
                        hint=f"Columns: {', '.join(table.column_names)}",
                    )
                )

        for column_name, column_rule in table_rule.columns.items():
            column = table.column(column_name)
            if column is None:
                issues.append(
                    Issue(
                        "error",
                        "unknown-column",
                        f"Unknown column {column_name!r} in table {table_name!r}.",
                        table=table_name,
                        column=column_name,
                        hint=f"Columns: {', '.join(table.column_names)}",
                    )
                )
                continue

            transformer = column_rule.transformer
            if transformer not in REGISTRY.names():
                issues.append(
                    Issue(
                        "error",
                        "unknown-transformer",
                        f"Unknown transformer {transformer!r}.",
                        table=table_name,
                        column=column_name,
                        hint=f"Available: {', '.join(REGISTRY.names())}",
                    )
                )
                continue

            issues.extend(_rule_issues(rules, transformer, column_rule, table, column_name))

        issues.extend(_unmasked_columns(rules, table, table_name))

    for child, child_column, _parent, _parent_column in schema.fk_pairs():
        child_rule = rules.tables.get(child, TableRule()).columns.get(child_column)
        transformer = child_rule.transformer if child_rule else "keep"
        issues.extend(_fk_issues(rules, schema, child, child_column, transformer))
    return issues


def _rule_issues(
    rules: RulesFile,
    transformer: str,
    rule: TransformerRule,
    table: TableInfo,
    column_name: str,
) -> list[Issue]:
    """Type, length and uniqueness problems for one column rule."""
    issues: list[Issue] = []
    column = table.column(column_name)
    assert column is not None  # caller checked
    kind = sql_kind(column.sa_type)
    where = {"table": table.name, "column": column_name}

    is_unique = column.is_unique if rule.unique is None else rule.unique
    if is_unique and not REGISTRY.get(transformer).supports_uniqueness:
        issues.append(
            Issue(
                "error",
                "uniqueness-impossible",
                f"'{transformer}' produces one fixed value, but {column_name} has a UNIQUE "
                "constraint, so the load would fail.",
                **where,
                hint=(
                    "Use a transformer with per-value entropy ('hash', 'fake', "
                    "'preserve_format', 'email'), or 'null'."
                ),
            )
        )

    if transformer == "number_noise" and kind not in _NUMERIC_KINDS:
        issues.append(
            Issue(
                "error",
                "type-mismatch",
                f"'number_noise' needs a numeric column, but {column_name} is {column.sa_type}.",
                **where,
            )
        )
    if transformer == "date_shift" and kind not in _DATE_KINDS | _STRING_KINDS:
        issues.append(
            Issue(
                "error",
                "type-mismatch",
                "'date_shift' needs a date/timestamp column, but "
                f"{column_name} is {column.sa_type}.",
                **where,
            )
        )
    if transformer in _TEXT_ONLY_TRANSFORMERS and kind not in _STRING_KINDS:
        issues.append(
            Issue(
                "error",
                "type-mismatch",
                f"'{transformer}' produces text, but {column_name} is {column.sa_type} "
                "and the value would not fit.",
                **where,
                hint="Use 'hash' (integer-safe) or 'shuffle' for numeric identifiers.",
            )
        )

    try:
        REGISTRY.get(transformer).params_model.model_validate(rule.params)
    except ValidationError as exc:
        issues.append(Issue("error", "invalid-params", format_validation_error(exc), **where))
        return issues

    if transformer == "null" and not column.nullable:
        issues.append(
            Issue("error", "null-not-allowed", "NULL cannot fit a NOT NULL column.", **where)
        )

    declared = column.length
    if declared and transformer == "hash":
        params = rule.params
        wanted = int(params.get("length", 12)) + len(str(params.get("prefix", "")))
        if wanted > declared:
            issues.append(
                Issue(
                    "warning",
                    "value-too-long",
                    f"'hash' would produce {wanted} characters but {column_name} holds {declared}; "
                    "output will be truncated.",
                    **where,
                    hint="Lower params.length, or widen the target column.",
                )
            )
    if declared and transformer == "partial_mask":
        keep = int(rule.params.get("keep_first", 0)) + int(rule.params.get("keep_last", 4))
        if keep > declared:
            issues.append(
                Issue(
                    "warning",
                    "partial-mask-too-wide",
                    f"keep_first + keep_last = {keep} exceeds the column width {declared}; "
                    "values will be fully masked.",
                    **where,
                )
            )
    return issues


def _fk_issues(
    rules: RulesFile,
    schema: ReflectedSchema,
    table_name: str,
    column_name: str,
    transformer: str,
) -> list[Issue]:
    """Warn when an FK would be masked on one side only, or differently."""
    issues: list[Issue] = []
    for child, child_column, parent, parent_column in schema.fk_pairs():
        if (child, child_column) != (table_name, column_name):
            continue
        parent_rule = rules.tables.get(parent)
        parent_transformer = (
            parent_rule.columns[parent_column].transformer
            if parent_rule and parent_column in parent_rule.columns
            else None
        )
        masked_here = transformer not in PASSTHROUGH_TRANSFORMERS
        masked_there = parent_transformer not in (None, *PASSTHROUGH_TRANSFORMERS)

        child_rule = rules.tables.get(table_name, TableRule()).columns.get(column_name)
        explicit_here = child_rule.namespace if child_rule else None
        parent_column_rule = parent_rule.columns.get(parent_column) if parent_rule else None
        explicit_there = parent_column_rule.namespace if parent_column_rule else None
        if (explicit_here is None) != (explicit_there is None) or (
            explicit_here is not None and explicit_here != explicit_there
        ):
            issues.append(
                Issue(
                    "warning",
                    "fk-namespace-mismatch",
                    f"{child}.{child_column} and {parent}.{parent_column} would mask "
                    "differently because their 'namespace' settings differ.",
                    table=child,
                    column=child_column,
                    hint="Give both columns the same namespace, or omit it on both.",
                )
            )

        if masked_here and not masked_there:
            issues.append(
                Issue(
                    "warning",
                    "fk-one-sided",
                    f"{child}.{child_column} is masked but its FK target "
                    f"{parent}.{parent_column} is not, so the relationship will break.",
                    table=child,
                    column=child_column,
                    hint=f"Give {parent}.{parent_column} the same transformer.",
                )
            )
        elif masked_there and not masked_here:
            issues.append(
                Issue(
                    "warning",
                    "fk-one-sided",
                    f"{parent}.{parent_column} is masked but {child}.{child_column} is not.",
                    table=child,
                    column=child_column,
                )
            )
        elif masked_there and parent_transformer != transformer:
            issues.append(
                Issue(
                    "warning",
                    "fk-transformer-mismatch",
                    f"{child}.{child_column} uses '{transformer}' but its FK target "
                    f"{parent}.{parent_column} uses '{parent_transformer}'. Different "
                    "transformers produce different outputs, so the join will break.",
                    table=child,
                    column=child_column,
                    hint=f"Use '{transformer}' with identical params on both columns.",
                )
            )
        if child_rule and parent_column_rule and masked_here and masked_there:
            if child_rule.params != parent_column_rule.params:
                issues.append(
                    Issue(
                        "warning",
                        "fk-params-mismatch",
                        f"{child}.{child_column} and {parent}.{parent_column} "
                        "use different params.",
                        table=child,
                        column=child_column,
                    )
                )
            if transformer in REGISTRY.names() and not REGISTRY.get(transformer).cross_table_stable:
                issues.append(
                    Issue(
                        "warning",
                        "fk-unstable-transformer",
                        f"'{transformer}' cannot preserve joins across {child} and {parent}.",
                        table=child,
                        column=child_column,
                    )
                )
    return issues


def _unmasked_columns(rules: RulesFile, table: TableInfo, table_name: str) -> list[Issue]:
    table_rule = rules.tables.get(table_name)
    if table_rule is None or table_rule.action in ("skip", "truncate"):
        return []
    return [
        Issue(
            "warning",
            "no-rule",
            f"{column.name} has no rule and will be copied verbatim.",
            table=table_name,
            column=column.name,
        )
        for column in table.columns
        if column.name not in table_rule.columns
    ]


# --------------------------------------------------------------------------- #
# Compilation
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class CompiledColumn:
    """One column plus the transformer that will mask it (``None`` = copy)."""

    name: str
    transformer: BaseTransformer[Any] | None


@dataclass(frozen=True)
class CompiledTable:
    """A table's rules, resolved against the schema and the key."""

    name: str
    action: TableAction
    subset_rows: int | None
    order_by: list[str]
    columns: dict[str, CompiledColumn]
    table: TableInfo = field(repr=False)

    @property
    def masked_columns(self) -> dict[str, BaseTransformer[Any]]:
        """Columns that will actually change. ``keep`` is not masking."""
        return {
            name: column.transformer
            for name, column in self.columns.items()
            if column.transformer is not None
            and column.transformer.name not in PASSTHROUGH_TRANSFORMERS
        }

    @property
    def unmasked_columns(self) -> list[str]:
        """Columns copied verbatim, whether by rule (``keep``) or by omission."""
        return [
            name
            for name, column in self.columns.items()
            if column.transformer is None or column.transformer.name in PASSTHROUGH_TRANSFORMERS
        ]

    @property
    def copies_rows(self) -> bool:
        return self.action in ("copy", "subset")


@dataclass(frozen=True)
class CompiledPlan:
    """Everything the engine needs: ordered tables with bound transformers."""

    tables: dict[str, CompiledTable]
    order: list[list[str]]
    settings: Settings

    def get(self, name: str) -> CompiledTable:
        return self.tables[name]

    @property
    def copied_tables(self) -> list[str]:
        return [
            name
            for group in self.order
            for name in group
            if name in self.tables and self.tables[name].copies_rows
        ]


def compile_rules(
    rules: RulesFile,
    schema: ReflectedSchema,
    key: SecretKey,
    *,
    only: list[str] | None = None,
) -> CompiledPlan:
    """Bind every rule to a concrete transformer instance.

    Raises :class:`~masker.errors.ConfigError` on anything that cannot be
    built (unknown transformer, bad params, impossible uniqueness).
    """
    settings = rules.settings
    selected = set(only) if only is not None else None
    namespaces = schema.fk_column_namespaces()
    compiled: dict[str, CompiledTable] = {}

    for group in schema.ordered_tables:
        for table_name in group:
            if selected is not None and table_name not in selected:
                continue
            table_rule = rules.tables.get(table_name, TableRule())
            table = schema.tables[table_name]
            columns: dict[str, CompiledColumn] = {}
            for column in table.columns:
                rule = table_rule.columns.get(column.name)
                if rule is None:
                    columns[column.name] = CompiledColumn(column.name, None)
                    continue
                columns[column.name] = CompiledColumn(
                    column.name,
                    _build_transformer(rule, table, column.name, key, settings, namespaces),
                )
            compiled[table_name] = CompiledTable(
                name=table_name,
                action=table_rule.action,
                subset_rows=table_rule.subset_rows or settings.subset_rows,
                order_by=list(table_rule.order_by),
                columns=columns,
                table=table,
            )
    linked: dict[str, list[BaseTransformer[Any]]] = {}
    for compiled_table in compiled.values():
        for transformer in compiled_table.masked_columns.values():
            if transformer.ctx.namespace:
                linked.setdefault(transformer.ctx.scope, []).append(transformer)
    for members in linked.values():
        canonical = next((member for member in members if member.ctx.is_unique), None)
        if canonical is None:
            continue
        for member in members:
            if member is canonical:
                continue
            if (
                member.name == canonical.name
                and member.params == canonical.params
                and sql_kind(member.ctx.sa_type) == sql_kind(canonical.ctx.sa_type)
                and member.ctx.length == canonical.ctx.length
            ):
                member.linked_transformer = canonical
    return CompiledPlan(tables=compiled, order=schema.ordered_tables, settings=settings)


def _build_transformer(
    rule: TransformerRule,
    table: TableInfo,
    column_name: str,
    key: SecretKey,
    settings: Settings,
    namespaces: dict[tuple[str, str], str] | None = None,
) -> BaseTransformer[Any]:
    column = table.column(column_name)
    assert column is not None  # validate_rules() checks this first
    is_unique = column.is_unique if rule.unique is None else rule.unique
    context = ColumnContext(
        table=table.name,
        column=column_name,
        key=key,
        namespace=rule.namespace or (namespaces or {}).get((table.name, column_name), ""),
        sa_type=column.sa_type,
        length=column.length,
        is_unique=is_unique,
        is_nullable=column.nullable,
        null_passthrough=(
            settings.null_passthrough if rule.on_null is None else rule.on_null == "keep"
        ),
        max_unique_attempts=settings.unique_max_attempts,
        locale=settings.locale,
    )
    return REGISTRY.build(rule.transformer, rule.params, context)

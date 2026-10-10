"""Schema reflection, the foreign-key graph, and table ordering.

Masker copies tables in dependency order so that a parent row always exists
before the child row that points at it. Where the FK graph contains a cycle
that is impossible, and Masker falls back to loading the cycle inside a single
transaction with foreign-key checks deferred (see README.md, Limitations).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import MetaData, Table, func, inspect, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.types import TypeEngine

from masker.errors import SchemaError

__all__ = [
    "ColumnInfo",
    "ForeignKeyInfo",
    "ReflectedSchema",
    "TableInfo",
    "fk_column_namespaces",
    "reflect_schema",
    "row_count",
    "table_groups",
]


@dataclass(frozen=True, slots=True)
class ColumnInfo:
    """A reflected column with the attributes masking decisions depend on."""

    name: str
    sa_type: TypeEngine[Any]
    nullable: bool = True
    is_primary_key: bool = False
    is_unique: bool = False
    is_autoincrement: bool = False

    @property
    def length(self) -> int | None:
        return getattr(self.sa_type, "length", None)


@dataclass(frozen=True, slots=True)
class ForeignKeyInfo:
    columns: tuple[str, ...]
    referred_table: str
    referred_columns: tuple[str, ...]
    name: str | None = None


@dataclass(frozen=True, slots=True)
class TableInfo:
    name: str
    table: Table
    columns: tuple[ColumnInfo, ...]
    foreign_keys: tuple[ForeignKeyInfo, ...]

    def column(self, name: str) -> ColumnInfo | None:
        return next((column for column in self.columns if column.name == name), None)

    @property
    def column_names(self) -> list[str]:
        return [column.name for column in self.columns]

    @property
    def primary_key(self) -> list[str]:
        return [column.name for column in self.columns if column.is_primary_key]

    @property
    def unique_columns(self) -> list[str]:
        return [column.name for column in self.columns if column.is_unique]

    @property
    def referenced_tables(self) -> list[str]:
        return sorted({fk.referred_table for fk in self.foreign_keys})


@dataclass(frozen=True)
class ReflectedSchema:
    """Everything Masker knows about a database's structure."""

    tables: dict[str, TableInfo]
    metadata: MetaData = field(repr=False)

    def get(self, name: str) -> TableInfo:
        try:
            return self.tables[name]
        except KeyError:
            raise SchemaError(
                f"Unknown table: {name!r}",
                hint=f"Reflected tables: {', '.join(sorted(self.tables)) or '<none>'}",
            ) from None

    @property
    def ordered_tables(self) -> list[list[str]]:
        """Tables in FK-safe order, grouped: a group of >1 is an FK cycle."""
        return table_groups(self.tables)

    @property
    def cycles(self) -> list[list[str]]:
        """Groups that need deferred foreign-key checks."""
        return [
            group
            for group in self.ordered_tables
            if len(group) > 1 or _has_self_reference(group, self.tables)
        ]

    def fk_column_namespaces(self) -> dict[tuple[str, str], str]:
        """One shared digest namespace per group of FK-linked columns.

        A primary key and every foreign key that references it must mask
        identically, so they all derive their values from the same namespace.
        Columns that are not part of any FK are absent from the mapping and
        fall back to ``table.column``.
        """
        return fk_column_namespaces(self)

    def fk_pairs(self) -> list[tuple[str, str, str, str]]:
        """``(child_table, child_column, parent_table, parent_column)`` triples."""
        pairs: list[tuple[str, str, str, str]] = []
        for table in self.tables.values():
            for fk in table.foreign_keys:
                child_columns = fk.columns
                parent_columns = fk.referred_columns
                for index, child_column in enumerate(child_columns):
                    pairs.append(
                        (table.name, child_column, fk.referred_table, parent_columns[index])
                    )
        return pairs


# --------------------------------------------------------------------------- #
# Reflection
# --------------------------------------------------------------------------- #
def reflect_schema(engine: Engine, *, only: list[str] | None = None) -> ReflectedSchema:
    """Reflect the whole schema (or a subset) into a :class:`ReflectedSchema`.

    The full schema is always inspected, even when ``only`` is given: foreign
    keys must resolve, and FK-consistency warnings need the whole picture.
    """
    try:
        inspector = inspect(engine)
        available = set(inspector.get_table_names())
    except SQLAlchemyError as exc:
        raise SchemaError(f"Could not inspect the database: {exc}") from exc

    if only:
        unknown = sorted(set(only) - available)
        if unknown:
            raise SchemaError(
                f"Unknown table(s): {', '.join(unknown)}",
                hint=f"Reflected tables: {', '.join(sorted(available)) or '<none>'}",
            )

    metadata = MetaData()
    try:
        metadata.reflect(bind=engine)
    except SQLAlchemyError as exc:
        raise SchemaError(f"Could not reflect the schema: {exc}") from exc

    tables: dict[str, TableInfo] = {}
    for name in sorted(available):
        table = metadata.tables.get(name)
        if table is None:  # pragma: no cover - reflection/inspection disagreement
            continue
        tables[name] = TableInfo(
            name=name,
            table=table,
            columns=_columns(engine, inspector, table, name),
            foreign_keys=_foreign_keys(table),
        )
    return ReflectedSchema(tables=tables, metadata=metadata)


def row_count(engine: Engine, table: Table) -> int:
    with engine.connect() as conn:
        return int(conn.execute(select(func.count()).select_from(table)).scalar_one())


# --------------------------------------------------------------------------- #
# Foreign-key namespaces
# --------------------------------------------------------------------------- #
def fk_column_namespaces(
    schema: ReflectedSchema,
) -> dict[tuple[str, str], str]:
    """Group FK-linked columns and name each group after its first member."""
    parents: dict[tuple[str, str], tuple[str, str]] = {}

    def find(node: tuple[str, str]) -> tuple[str, str]:
        root = node
        while parents.get(root, root) != root:
            root = parents[root]
        while parents.get(node, node) != root:  # path compression
            parents[node], node = root, parents[node]
        return root

    def union(left: tuple[str, str], right: tuple[str, str]) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parents[max(left_root, right_root)] = min(left_root, right_root)

    for child_table, child_column, parent_table, parent_column in schema.fk_pairs():
        child = (child_table, child_column)
        parent = (parent_table, parent_column)
        parents.setdefault(child, child)
        parents.setdefault(parent, parent)
        union(child, parent)

    groups: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for member in parents:
        groups.setdefault(find(member), []).append(member)
    return {
        member: f"{root[0]}.{root[1]}" for root, members in groups.items() for member in members
    }


# --------------------------------------------------------------------------- #
# Ordering
# --------------------------------------------------------------------------- #
def table_groups(tables: dict[str, TableInfo]) -> list[list[str]]:
    """Topologically sort tables into FK-safe groups.

    Returns a list of groups. Each group is a strongly connected component: a
    group of one table can be loaded on its own, a group of several tables is
    an FK cycle that must be loaded together with constraints deferred.
    """
    edges: dict[str, set[str]] = {name: set() for name in tables}
    for name, info in tables.items():
        for referenced in info.referenced_tables:
            if referenced in edges and referenced != name:
                edges[referenced].add(name)

    components = _strongly_connected(sorted(tables), edges)
    return _topological_condensation(components, edges)


def _strongly_connected(nodes: list[str], edges: dict[str, set[str]]) -> list[list[str]]:
    """Iterative Tarjan's algorithm (no recursion limit on wide schemas)."""
    indices: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    components: list[list[str]] = []
    counter = 0

    for root in nodes:
        if root in indices:
            continue
        indices[root] = lowlink[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        work: list[tuple[str, list[str]]] = [(root, sorted(edges.get(root, ())))]

        while work:
            node, children = work[-1]
            descended = False
            for child in children:
                if child not in indices:
                    indices[child] = lowlink[child] = counter
                    counter += 1
                    stack.append(child)
                    on_stack.add(child)
                    work.append((child, sorted(edges.get(child, ()))))
                    descended = True
                    break
                if child in on_stack:
                    lowlink[node] = min(lowlink[node], indices[child])
            if descended:
                continue

            work.pop()
            if lowlink[node] == indices[node]:
                component: list[str] = []
                while True:
                    popped = stack.pop()
                    on_stack.discard(popped)
                    component.append(popped)
                    if popped == node:
                        break
                components.append(sorted(component))
            if work:
                parent = work[-1][0]
                lowlink[parent] = min(lowlink[parent], lowlink[node])

    return components


def _topological_condensation(
    components: list[list[str]], edges: dict[str, set[str]]
) -> list[list[str]]:
    """Kahn's algorithm over the graph of components."""
    component_of = {name: index for index, names in enumerate(components) for name in names}
    successors: dict[int, set[int]] = {index: set() for index in range(len(components))}
    indegree = dict.fromkeys(range(len(components)), 0)

    for source, targets in edges.items():
        source_component = component_of[source]
        for target in targets:
            target_component = component_of[target]
            if source_component == target_component:
                continue
            if target_component not in successors[source_component]:
                successors[source_component].add(target_component)
                indegree[target_component] += 1

    ready = deque(sorted(index for index, degree in indegree.items() if degree == 0))
    ordered: list[list[str]] = []
    while ready:
        index = ready.popleft()
        ordered.append(components[index])
        for successor in sorted(successors[index]):
            indegree[successor] -= 1
            if indegree[successor] == 0:
                ready.append(successor)

    if len(ordered) != len(components):  # pragma: no cover - unreachable after Tarjan
        missing = [c for c in components if c not in ordered]
        raise SchemaError(
            "Could not order these tables: "
            + ", ".join(name for group in missing for name in group)
        )
    return ordered


def _has_self_reference(group: list[str], tables: dict[str, TableInfo]) -> bool:
    """True when a table in the group points at itself."""
    return any(name in tables[name].referenced_tables for name in group if name in tables)


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #
def _columns(engine: Engine, inspector: Any, table: Table, name: str) -> tuple[ColumnInfo, ...]:
    unique_names = _unique_column_names(inspector, name)
    if engine.dialect.name == "sqlite":
        unique_names |= _sqlite_unique_columns(engine, name)
    primary_key = set(inspector.get_pk_constraint(name).get("constrained_columns") or [])
    out: list[ColumnInfo] = []
    for column in table.columns:
        out.append(
            ColumnInfo(
                name=column.name,
                sa_type=column.type,
                nullable=bool(column.nullable),
                is_primary_key=column.name in primary_key,
                is_unique=column.name in unique_names
                or (column.name in primary_key and len(primary_key) == 1),
                is_autoincrement=bool(column.autoincrement is True),
            )
        )
    return tuple(out)


def _unique_column_names(inspector: Any, name: str) -> set[str]:
    """Single-column UNIQUE constraints and unique indexes.

    Composite constraints are deliberately excluded: no single column in them
    is unique on its own.
    """
    unique: set[str] = set()
    try:
        constraints = inspector.get_unique_constraints(name)
    except NotImplementedError:  # pragma: no cover - some dialects lack this
        constraints = []
    for constraint in constraints:
        columns = constraint.get("column_names") or []
        if len(columns) == 1:
            unique.add(columns[0])
    try:
        indexes = inspector.get_indexes(name)
    except NotImplementedError:  # pragma: no cover - some dialects lack this
        indexes = []
    for index in indexes:
        columns = index.get("column_names") or []
        if index.get("unique") and len(columns) == 1:
            unique.add(columns[0])
    return unique


def _sqlite_unique_columns(engine: Engine, name: str) -> set[str]:
    """Single-column UNIQUE columns via ``PRAGMA index_list``.

    SQLite reports an inline ``UNIQUE`` as a hidden ``sqlite_autoindex_*``,
    which ``get_indexes()`` does not surface, so it has to be asked directly.
    """
    unique: set[str] = set()
    with engine.connect() as conn:
        for row in conn.exec_driver_sql(
            f'PRAGMA index_list("{name.replace(chr(34), chr(34) * 2)}")'
        ):
            if not row[2]:  # not unique
                continue
            info = list(
                conn.exec_driver_sql(
                    f'PRAGMA index_info("{str(row[1]).replace(chr(34), chr(34) * 2)}")'
                )
            )
            if len(info) == 1:
                unique.add(str(info[0][2]))
    return unique


def _foreign_keys(table: Table) -> tuple[ForeignKeyInfo, ...]:
    out: list[ForeignKeyInfo] = []
    for constraint in table.foreign_key_constraints:
        referred = next(iter(constraint.elements)).column.table
        # SQLAlchemy models an unnamed constraint with a sentinel, not None.
        raw_name = constraint.name
        out.append(
            ForeignKeyInfo(
                columns=tuple(column.name for column in constraint.columns),
                referred_table=referred.name,
                referred_columns=tuple(element.column.name for element in constraint.elements),
                name=raw_name if isinstance(raw_name, str) else None,
            )
        )
    return tuple(sorted(out, key=lambda fk: (fk.referred_table, fk.columns)))

"""The transformer interface, its registry, and the shared behaviours.

Every transformer is a small class that turns one original value into one
masked value. Three cross-cutting concerns live here so that no transformer
has to re-implement them:

* **determinism** -- randomness comes only from
  ``HMAC(key, table|column|value)``, exposed as :meth:`ColumnContext.rng`;
* **uniqueness** -- unique columns get a retry loop with a counter salt;
* **fit** -- results are coerced to the column's SQL type and truncated to its
  declared length.

See ``CONTRIBUTING.md`` for the "add a transformer" walkthrough.
"""

from __future__ import annotations

import random
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar, Generic, TypeVar, cast

from pydantic import BaseModel, ConfigDict
from sqlalchemy.types import TypeEngine

from masker.errors import TransformerError, UniquenessError
from masker.keys import SecretKey
from masker.values import fit_value

__all__ = [
    "BaseParams",
    "BaseTransformer",
    "ColumnContext",
    "TransformerRegistry",
]

P = TypeVar("P", bound="BaseParams")


class BaseParams(BaseModel):
    """Base class for transformer params: unknown keys are a hard error."""

    model_config = ConfigDict(extra="forbid", frozen=True)


@dataclass(frozen=True, slots=True)
class ColumnContext:
    """Everything a transformer needs to know about the column it masks."""

    table: str
    column: str
    key: SecretKey
    sa_type: TypeEngine[Any]
    #: Digest namespace. Defaults to ``table.column``; columns joined by a
    #: foreign key share one namespace so they mask identically.
    namespace: str = ""
    length: int | None = None
    is_unique: bool = False
    is_nullable: bool = True
    null_passthrough: bool = True
    max_unique_attempts: int = 1000
    locale: str | None = None

    @property
    def qualified(self) -> str:
        return f"{self.table}.{self.column}"

    @property
    def scope(self) -> str:
        """The namespace every digest for this column is derived from."""
        return self.namespace or self.qualified

    def digest(self, *parts: str | int | bytes) -> bytes:
        """Keyed digest, namespaced by this column's scope."""
        return self.key.digest(self.scope, *parts)

    def int_digest(self, *parts: str | int | bytes, n_bytes: int = 8) -> int:
        return self.key.int_digest(self.scope, *parts, n_bytes=n_bytes)

    def hex_digest(self, *parts: str | int | bytes, length: int = 12) -> str:
        return self.key.hex_digest(self.scope, *parts, length=length)

    def rng(self, *parts: str | int | bytes) -> random.Random:
        """A deterministic PRNG stream for one original value."""
        return self.key.stream(self.scope, *parts)

    def fit(self, value: Any) -> Any:
        return fit_value(value, self.sa_type, length=self.length)


class BaseTransformer(ABC, Generic[P]):
    """A single-value transformation, bound to one table column."""

    #: Registry name, as written in ``masker.yaml``.
    name: ClassVar[str] = ""
    #: One-line description shown by ``masker transformers``.
    summary: ClassVar[str] = ""
    #: Pydantic model validating ``params``.
    params_model: ClassVar[type[BaseParams]] = BaseParams
    #: Can this transformer ever satisfy a UNIQUE constraint?
    supports_uniqueness: ClassVar[bool] = True
    #: Does it maintain its own seen-set? ``False`` when uniqueness is
    #: guaranteed by construction (``keep``, ``shuffle``).
    tracks_uniqueness: ClassVar[bool] = True
    #: ``False`` when the output depends on other rows in the column.
    value_scoped: ClassVar[bool] = True
    #: ``False`` when the same input maps to different outputs in different
    #: tables (so joins across tables are *not* preserved).
    cross_table_stable: ClassVar[bool] = True
    #: ``True`` when the transformer needs the column's distinct values before
    #: the first row is masked (see :meth:`prepare`).
    requires_prepass: ClassVar[bool] = False
    #: ``True`` when the masked value stays inside the original value's domain,
    #: so a masked value can legitimately coincide with *another* row's
    #: original (``date_shift``, ``number_noise``). ``masker verify`` reports
    #: those as a warning rather than a leak.
    preserves_domain: ClassVar[bool] = False

    def __init__(self, params: Mapping[str, Any] | None, ctx: ColumnContext) -> None:
        self.ctx = ctx
        model = type(self).params_model
        try:
            validated = model.model_validate(dict(params or {}))
        except Exception as exc:
            raise TransformerError(
                f"Invalid params for '{self.name}' on {ctx.qualified}: {_pydantic_summary(exc)}"
            ) from exc
        self.params: P = cast(P, validated)
        self._seen: set[Any] = set()
        self.retries: int = 0
        self._resolved: dict[Any, Any] = {}
        self.linked_transformer: BaseTransformer[Any] | None = None

        if ctx.is_unique and not type(self).supports_uniqueness:
            raise TransformerError(
                f"'{self.name}' cannot produce unique values, but {ctx.qualified} has a "
                "UNIQUE constraint.",
                hint=(
                    "Use a transformer with per-value entropy for this column "
                    "('hash', 'fake', 'preserve_format', 'email'), or drop the constraint."
                ),
            )

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def __call__(self, value: Any) -> Any:
        return self.apply(value)

    def apply(self, value: Any) -> Any:
        """Mask one value, enforcing NULL handling, uniqueness and fit."""
        if value is None and self.ctx.null_passthrough:
            return None

        if self.linked_transformer is not None:
            return self.ctx.fit(self.linked_transformer(value))
        original_key = self._hashable(value)
        if self.ctx.is_unique and original_key in self._resolved:
            return self._resolved[original_key]

        attempt = 0
        while True:
            candidate = self.ctx.fit(self._apply(value, attempt))
            if candidate is None and not self.ctx.is_nullable:
                raise TransformerError(
                    f"{self.ctx.qualified} is NOT NULL but its rule produced NULL."
                )

            if not self.ctx.is_unique or candidate is None or not self.tracks_uniqueness:
                return candidate

            seen_key = self._hashable(candidate)
            if seen_key not in self._seen:
                self._seen.add(seen_key)
                self._resolved[original_key] = candidate
                return candidate

            attempt += 1
            self.retries += 1
            if attempt >= self.ctx.max_unique_attempts:
                raise UniquenessError(
                    f"'{self.name}' on {self.ctx.qualified} could not produce a unique value "
                    f"after {attempt} attempts.",
                    hint=(
                        "Pick a transformer with more entropy for this column (for example "
                        "'hash' or 'fake'), or raise settings.unique_max_attempts."
                    ),
                )

    def prepare(self, values: Iterable[Any]) -> None:
        """Optional hook: inspect the column before any row is masked.

        Called once per table, in primary-key order, only for transformers
        with ``requires_prepass = True``.
        """

    def describe(self) -> str:
        """Short human description, used in ``--dry-run`` plans and reports."""
        params = self.params.model_dump(exclude_defaults=True)
        rendered = ", ".join(f"{key}={value!r}" for key, value in sorted(params.items()))
        return f"{self.name}({rendered})" if rendered else self.name

    # ------------------------------------------------------------------ #
    # Subclass API
    # ------------------------------------------------------------------ #
    @abstractmethod
    def _apply(self, value: Any, attempt: int) -> Any:
        """Produce a masked value.

        ``attempt`` is 0 for the first try and increases while uniqueness
        retries are needed; mix it into the keyed digest so retries yield
        different output.
        """

    # ------------------------------------------------------------------ #
    # Helpers for subclasses
    # ------------------------------------------------------------------ #
    def require_not_null(self, value: Any) -> Any:
        if value is None:
            raise TransformerError(
                f"'{self.name}' on {self.ctx.qualified} received NULL but "
                "settings.null_passthrough is false.",
                hint="Set null_passthrough: true (the default) or use a transformer that "
                "handles NULL, such as 'constant'.",
            )
        return value

    @staticmethod
    def _hashable(value: Any) -> Any:
        try:
            hash(value)
        except TypeError:
            return repr(value)
        return value


def _pydantic_summary(exc: Exception) -> str:
    errors = getattr(exc, "errors", None)
    if callable(errors):
        parts = []
        for err in errors():
            loc = err.get("loc") or ()
            where = ".".join(str(part) for part in loc) if loc else "params"
            parts.append(f"{where}: {err.get('msg', 'invalid')}")
        if parts:
            return "; ".join(parts)
    return str(exc)


@dataclass(slots=True)
class TransformerRegistry:
    """Name -> transformer class, with a helpful error on typos."""

    _by_name: dict[str, type[BaseTransformer[Any]]] = field(default_factory=dict)

    def register(self, cls: type[BaseTransformer[Any]]) -> type[BaseTransformer[Any]]:
        if not cls.name:
            raise ValueError(f"{cls.__name__} does not define a 'name'")
        if cls.name in self._by_name:
            raise ValueError(f"Duplicate transformer name: {cls.name!r}")
        self._by_name[cls.name] = cls
        return cls

    def get(self, name: str) -> type[BaseTransformer[Any]]:
        try:
            return self._by_name[name]
        except KeyError:
            raise TransformerError(
                f"Unknown transformer: {name!r}",
                hint=f"Available transformers: {', '.join(sorted(self._by_name))}",
            ) from None

    def build(
        self,
        name: str,
        params: Mapping[str, Any] | None,
        ctx: ColumnContext,
    ) -> BaseTransformer[Any]:
        return self.get(name)(params, ctx)

    def names(self) -> list[str]:
        return sorted(self._by_name)

    def items(self) -> list[tuple[str, type[BaseTransformer[Any]]]]:
        return sorted(self._by_name.items())

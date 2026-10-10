"""``shuffle`` -- permute the existing values of a column among themselves.

```yaml
columns:
  email: {transformer: shuffle}
```

Shuffle runs in **two passes**: Masker first reads the column's distinct values
(``SELECT DISTINCT ... ORDER BY``), builds a complete random permutation of
them with a keyed Sattolo permutation, and then streams the rows
against that frozen permutation. The permutation is therefore a bijection --
uniqueness is preserved -- and it is stable across runs because the values are
ordered by value, not by storage order.

Two consequences worth knowing:

* every distinct value of the column is held in memory while the table is
  copied, so shuffle is unsuitable for columns with tens of millions of
  distinct values;
* the mapping is column-scoped, so the same email in two different tables gets
  two different replacements and joins across tables are **not** preserved.
  Use ``hash``, ``fake`` or ``email`` when you need that.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, ClassVar

from masker.errors import TransformerError
from masker.transformers.base import BaseParams, BaseTransformer, ColumnContext
from masker.transformers.registry import register

__all__ = ["ShuffleParams", "ShuffleTransformer"]


class ShuffleParams(BaseParams):
    pass


@register
class ShuffleTransformer(BaseTransformer[ShuffleParams]):
    name = "shuffle"
    summary = "Permute the column's own values among themselves."
    params_model = ShuffleParams
    value_scoped: ClassVar[bool] = False
    cross_table_stable: ClassVar[bool] = False
    tracks_uniqueness: ClassVar[bool] = False
    requires_prepass: ClassVar[bool] = True

    def __init__(self, params: Mapping[str, Any] | None, ctx: ColumnContext) -> None:
        super().__init__(params, ctx)
        self._mapping: dict[Any, Any] = {}
        #: Values seen in the second pass that the first pass did not see.
        #: Can only happen if the source changed mid-run.
        self.unmapped = 0

    def prepare(self, values: Iterable[Any]) -> None:
        """Build the full permutation from the column's distinct values."""
        originals = [_hashable(value) for value in values if value is not None]
        count = len(originals)
        order = list(range(count))
        if count == 1:
            raise TransformerError(
                f"Shuffle cannot change {self.ctx.qualified}: only one distinct value exists."
            )
        for index in range(count - 1, 0, -1):
            value = originals[index]
            slot = self.ctx.rng(value, index).randint(0, index - 1)
            order[index], order[slot] = order[slot], order[index]
        self._mapping = {originals[index]: originals[order[index]] for index in range(count)}

    def _apply(self, value: Any, attempt: int) -> Any:
        self.require_not_null(value)
        key = _hashable(value)
        mapped = self._mapping.get(key, _MISSING)
        if mapped is not _MISSING:
            return mapped
        self.unmapped += 1
        raise TransformerError(
            f"The source changed while shuffling {self.ctx.qualified}; rerun on a stable snapshot."
        )

    @property
    def distinct_values_seen(self) -> int:
        """How many distinct values are held in memory right now."""
        return len(self._mapping)


class _Missing:
    __slots__ = ()


_MISSING = _Missing()


def _hashable(value: Any) -> Any:
    try:
        hash(value)
    except TypeError as exc:
        raise TransformerError(
            f"'shuffle' needs hashable values, but got {type(value).__name__}.",
            hint="Use 'redact' or 'null' for JSON/BLOB-like columns instead.",
        ) from exc
    return value

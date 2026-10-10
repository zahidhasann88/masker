"""``hash`` -- keyed, truncated hash. Irreversible, join-preserving.

```yaml
columns:
  customer_id_ext: {transformer: hash, params: {length: 16}}
  national_id:     {transformer: hash, params: {length: 8, prefix: "ID-"}}
  user_id:         {transformer: hash}          # INTEGER column -> integer
```

The same original value always hashes to the same output, so a masked primary
key and the foreign keys pointing at it stay consistent -- as long as both
sides use ``hash`` with the same params.

On text columns the digest is rendered as hex and truncated to ``length``. On
integer columns it is rendered as a positive integer sized to the column
(``BIGINT`` gets 63 bits, ``INTEGER`` gets 31), which is what makes it possible
to mask surrogate keys without widening the column.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field
from sqlalchemy.types import BigInteger, SmallInteger

from masker.errors import TransformerError
from masker.transformers.base import BaseParams, BaseTransformer, ColumnContext
from masker.transformers.registry import register
from masker.values import sql_kind

__all__ = ["HashParams", "HashTransformer"]


class HashParams(BaseParams):
    length: int = Field(default=12, ge=1, le=64)
    prefix: str = ""
    uppercase: bool = False
    #: ``None`` (default) picks from the column type: hex for text, integer
    #: for integer columns.
    as_number: bool | None = None


@register
class HashTransformer(BaseTransformer[HashParams]):
    name = "hash"
    summary = "HMAC of the original value: hex for text columns, integer for integer columns."
    params_model = HashParams

    def __init__(self, params: Mapping[str, Any] | None, ctx: ColumnContext) -> None:
        super().__init__(params, ctx)
        kind = sql_kind(ctx.sa_type)
        as_number = kind == "integer" if self.params.as_number is None else self.params.as_number
        if not as_number:
            self._bits = 0
            return
        if kind != "integer":
            raise TransformerError(
                f"'hash' with as_number: true needs an integer column, but "
                f"{ctx.qualified} is {ctx.sa_type}.",
                hint="Drop as_number, or use 'number_noise' for decimal columns.",
            )
        if self.params.prefix:
            raise TransformerError(
                f"'hash' cannot add the prefix {self.params.prefix!r} to an integer "
                f"value in {ctx.qualified}.",
                hint="Remove params.prefix, or store the hash in a text column.",
            )
        self._bits = (
            63
            if isinstance(ctx.sa_type, BigInteger)
            else 15
            if isinstance(ctx.sa_type, SmallInteger)
            else 31
        )

    def _apply(self, value: Any, attempt: int) -> Any:
        self.require_not_null(value)
        if self._bits:
            return self.ctx.int_digest(_stable(value), attempt, n_bytes=8) % (2**self._bits)
        hex_digest = self.ctx.hex_digest(_stable(value), attempt, length=self.params.length)
        if self.params.uppercase:
            hex_digest = hex_digest.upper()
        return f"{self.params.prefix}{hex_digest}"


def _stable(value: Any) -> str:
    return value if isinstance(value, str) else repr(value)

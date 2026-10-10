"""``number_noise`` -- add bounded jitter to a number.

```yaml
columns:
  salary: {transformer: number_noise, params: {percent: 10}}
  score:  {transformer: number_noise, params: {min_delta: -3, max_delta: 3}}
  price:  {transformer: number_noise, params: {percent: 5, round_to: 2}}
```

Distributions, sums and averages stay roughly where they were, which is the
point: a masked analytics table should still be usable for analytics.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any, ClassVar

from masker.errors import TransformerError
from masker.transformers.base import BaseParams, BaseTransformer
from masker.transformers.registry import register
from masker.values import sql_kind

__all__ = ["NumberNoiseParams", "NumberNoiseTransformer"]


class NumberNoiseParams(BaseParams):
    #: Absolute jitter window. Omit both to use ``percent`` (default 10).
    min_delta: float | None = None
    max_delta: float | None = None
    #: Relative jitter window, in percent of the original value.
    percent: float | None = None
    #: Decimal places to round to. Defaults to the column's scale.
    round_to: int | None = None


@register
class NumberNoiseTransformer(BaseTransformer[NumberNoiseParams]):
    name = "number_noise"
    summary = "Add bounded random jitter to a number."
    params_model = NumberNoiseParams
    preserves_domain: ClassVar[bool] = True

    def _apply(self, value: Any, attempt: int) -> Any:
        self.require_not_null(value)
        number = self._as_number(value)
        low, high = self._window(number)
        jitter = self.ctx.rng(_stable(value), attempt).uniform(low, high)
        return self._round(number + jitter)

    # ------------------------------------------------------------------ #
    def _window(self, number: float) -> tuple[float, float]:
        params = self.params
        if params.min_delta is not None or params.max_delta is not None:
            low = params.min_delta if params.min_delta is not None else -(params.max_delta or 0.0)
            high = params.max_delta if params.max_delta is not None else -(params.min_delta or 0.0)
            if low > high:
                low, high = high, low
            return low, high
        percent = params.percent if params.percent is not None else 10.0
        spread = abs(number) * percent / 100.0
        return -spread, spread

    def _round(self, number: float) -> Any:
        params = self.params
        kind = sql_kind(self.ctx.sa_type)
        scale = params.round_to
        if scale is None:
            if kind == "integer":
                scale = 0
            elif kind == "numeric":
                column_scale = getattr(self.ctx.sa_type, "scale", None)
                scale = int(column_scale) if isinstance(column_scale, int) else None
        if scale is None:
            return number
        rounded = round(number, scale)
        return int(rounded) if scale == 0 else rounded

    def _as_number(self, value: Any) -> float:
        if isinstance(value, bool):
            raise TransformerError(
                f"'number_noise' does not apply to the boolean column {self.ctx.qualified}.",
                hint="Use 'constant', 'null' or 'shuffle' for booleans.",
            )
        if isinstance(value, (int, float, Decimal)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value.strip())
            except ValueError as exc:
                raise TransformerError(
                    f"'number_noise' cannot parse a value in {self.ctx.qualified} as a number."
                ) from exc
        raise TransformerError(
            f"'number_noise' cannot handle a {type(value).__name__} value in {self.ctx.qualified}.",
            hint="Use 'number_noise' on numeric columns only.",
        )


def _stable(value: Any) -> str:
    return format(value, "f") if isinstance(value, Decimal) else str(value)

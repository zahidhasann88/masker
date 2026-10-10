"""``date_shift`` -- move a date by a bounded, keyed random offset.

```yaml
columns:
  date_of_birth: {transformer: date_shift, params: {min_days: -30, max_days: 30}}
  created_at:    {transformer: date_shift, params: {min_days: -720, max_days: 720}}
```

The same original date receives a repeatable offset. Independent per-value
offsets can change relative ordering and intervals. Works on ``DATE``, ``DATETIME``/``TIMESTAMP``
columns and on ISO-8601 strings.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from typing import Any, ClassVar, cast

from pydantic import model_validator

from masker.errors import TransformerError
from masker.transformers.base import BaseParams, BaseTransformer, ColumnContext
from masker.transformers.registry import register
from masker.values import coerce, sql_kind

__all__ = ["DateShiftParams", "DateShiftTransformer"]

_SECONDS_PER_DAY = 86400


class DateShiftParams(BaseParams):
    min_days: int = -365
    max_days: int = 365
    min_seconds: int = 0
    max_seconds: int = 0
    #: Optional ISO-8601 bounds; shifted values are clamped into this window.
    clamp_min: str | None = None
    clamp_max: str | None = None

    @model_validator(mode="after")
    def _check_bounds(self) -> DateShiftParams:
        low = self.min_days * _SECONDS_PER_DAY + self.min_seconds
        high = self.max_days * _SECONDS_PER_DAY + self.max_seconds
        if low > high:
            raise ValueError("min_days/min_seconds must not exceed max_days/max_seconds")
        return self


@register
class DateShiftTransformer(BaseTransformer[DateShiftParams]):
    name = "date_shift"
    summary = "Shift dates and timestamps by a bounded random offset."
    params_model = DateShiftParams
    preserves_domain: ClassVar[bool] = True

    def __init__(self, params: Mapping[str, Any] | None, ctx: ColumnContext) -> None:
        super().__init__(params, ctx)
        self._floor = self._parse_bound(self.params.clamp_min)
        self._ceiling = self._parse_bound(self.params.clamp_max)

    def _apply(self, value: Any, attempt: int) -> Any:
        self.require_not_null(value)
        kind = sql_kind(self.ctx.sa_type)

        if isinstance(value, (dt.date, dt.datetime)):
            return self._shift(value, attempt)
        if isinstance(value, str):
            return self._shift_string(value, attempt)
        if kind in ("date", "datetime"):
            return self._shift(coerce(value, dt.datetime), attempt)

        raise TransformerError(
            f"'date_shift' cannot handle a {type(value).__name__} value in "
            f"{self.ctx.qualified} (column type {self.ctx.sa_type}).",
            hint="Use 'date_shift' on DATE/TIMESTAMP columns or ISO-8601 strings.",
        )

    # ------------------------------------------------------------------ #
    def _offset(self, value: Any, attempt: int) -> dt.timedelta:
        params = self.params
        low = params.min_days * _SECONDS_PER_DAY + params.min_seconds
        high = params.max_days * _SECONDS_PER_DAY + params.max_seconds
        seconds = self.ctx.rng(_stable(value), attempt).randint(low, high)
        return dt.timedelta(seconds=seconds)

    def _shift(self, value: dt.date | dt.datetime, attempt: int) -> dt.date | dt.datetime:
        offset = self._offset(value, attempt)
        if isinstance(value, dt.datetime):
            return self._clamp(value + offset, is_datetime=True)
        # A plain DATE has no time part; shift in whole days.
        return self._clamp(value + dt.timedelta(days=offset.days), is_datetime=False)

    def _shift_string(self, value: str, attempt: int) -> str:
        text = value.strip()
        parsed = coerce(text, dt.datetime)
        assert isinstance(parsed, dt.datetime)
        shifted = self._shift(parsed, attempt)
        assert isinstance(shifted, dt.datetime)  # datetime in, datetime out
        if len(text) == 10 and text[4] == "-" and text[7] == "-":
            return shifted.date().isoformat()
        if "T" in text:
            return shifted.isoformat()
        return shifted.strftime("%Y-%m-%d %H:%M:%S")

    def _clamp(self, value: dt.date | dt.datetime, *, is_datetime: bool) -> dt.date | dt.datetime:
        if isinstance(value, dt.datetime):
            as_datetime = value
        else:
            as_datetime = dt.datetime(value.year, value.month, value.day)
        if self._floor is not None and as_datetime < self._floor:
            as_datetime = self._floor
        if self._ceiling is not None and as_datetime > self._ceiling:
            as_datetime = self._ceiling
        return as_datetime if is_datetime else as_datetime.date()

    @staticmethod
    def _parse_bound(bound: str | None) -> dt.datetime | None:
        if bound is None:
            return None
        parsed = coerce(bound, dt.datetime)
        return cast(dt.datetime, parsed)


def _stable(value: Any) -> str:
    return value.isoformat() if isinstance(value, (dt.date, dt.datetime)) else str(value)

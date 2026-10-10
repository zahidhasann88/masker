"""Value coercion and length fitting.

Masked output must always fit the target column. Every transformer result
passes through :func:`fit_value`, which coerces it to the column's SQL type and
truncates strings to the declared length. Coercion that would lose information
silently is refused with a :class:`~masker.errors.TransformerError` instead.
"""

from __future__ import annotations

import datetime as dt
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any

from sqlalchemy.types import (
    JSON,
    BigInteger,
    Boolean,
    Date,
    DateTime,
    Float,
    Integer,
    LargeBinary,
    Numeric,
    SmallInteger,
    String,
    Time,
    TypeEngine,
)

from masker.errors import TransformerError

__all__ = ["ISO_DATE", "coerce", "fit_value", "sql_kind"]

ISO_DATE = "%Y-%m-%d"
ISO_DATETIME = "%Y-%m-%d %H:%M:%S"


def sql_kind(sa_type: Any) -> str:
    """A coarse, dialect-independent label for a SQLAlchemy column type."""
    if isinstance(sa_type, DateTime):  # must precede Date: DateTime subclasses Date
        return "datetime"
    if isinstance(sa_type, Date):
        return "date"
    if isinstance(sa_type, Time):
        return "time"
    if isinstance(sa_type, (BigInteger, Integer, SmallInteger)):
        return "integer"
    if isinstance(sa_type, Float):
        return "float"
    if isinstance(sa_type, Numeric):
        return "numeric"
    if isinstance(sa_type, Boolean):
        return "boolean"
    if isinstance(sa_type, LargeBinary):
        return "binary"
    if isinstance(sa_type, JSON):
        return "json"
    if isinstance(sa_type, String):
        return "string"
    return "unknown"


def fit_value(value: Any, sa_type: Any, *, length: int | None = None) -> Any:
    """Coerce ``value`` so it is storable in a column of type ``sa_type``.

    ``length`` is the declared column length for string columns; longer values
    are truncated rather than rejected, because a rejected row would abort an
    otherwise valid run.
    """
    if value is None:
        return None

    kind = sql_kind(sa_type)
    try:
        if kind == "string":
            text = value if isinstance(value, str) else _stringify(value)
            limit = length if length is not None else getattr(sa_type, "length", None)
            if limit and len(text) > limit:
                text = text[:limit]
            return text
        if kind == "integer":
            return coerce(value, int)
        if kind == "numeric":
            scale = getattr(sa_type, "scale", None)
            return _to_decimal(value, scale)
        if kind == "float":
            return float(value)
        if kind == "boolean":
            return coerce(value, bool)
        if kind == "date":
            return coerce(value, dt.date)
        if kind == "datetime":
            return coerce(value, dt.datetime)
        if kind == "time":
            return coerce(value, dt.time)
        if kind == "binary":
            return (
                value if isinstance(value, (bytes, bytearray, memoryview)) else str(value).encode()
            )
    except TransformerError:
        raise
    except (TypeError, ValueError, ArithmeticError) as exc:
        raise TransformerError(
            f"Masked value of type {type(value).__name__} does not fit the {kind} column type.",
            hint="Check the transformer's params, or widen the target column.",
        ) from exc
    return value


def coerce(value: Any, target: type) -> Any:
    """Convert ``value`` to ``target`` using tolerant, explicit rules."""
    if value is None:
        return None
    if target is int:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            if not value.is_integer():
                raise ValueError("Value is not a whole number")
            return int(value)
        if isinstance(value, Decimal):
            if value != value.to_integral_value():
                raise ValueError("Decimal is not a whole number")
            return int(value)
        return int(str(value).strip())
    if target is bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float, Decimal)):
            return bool(value)
        return _parse_bool(str(value))
    if target is float:
        return float(value)
    if target is dt.date:
        return _to_date(value)
    if target is dt.datetime:
        return _to_datetime(value)
    if target is dt.time:
        if isinstance(value, dt.datetime):
            return value.time()
        if isinstance(value, dt.time):
            return value
        return dt.time.fromisoformat(str(value).strip())
    if target is str:
        return _stringify(value)
    raise TransformerError(f"No coercion rule for target type {target.__name__}")


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #
def _stringify(value: Any) -> str:
    if isinstance(value, dt.datetime):
        return value.strftime(ISO_DATETIME)
    if isinstance(value, (dt.date, dt.time)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return format(value, "f")
    return str(value)


def _to_decimal(value: Any, scale: int | None) -> Decimal:
    if isinstance(value, Decimal):
        decimal = value
    else:
        try:
            decimal = Decimal(str(value))
        except InvalidOperation as exc:
            raise ValueError("Value is not a number") from exc
    if scale is not None and scale >= 0:
        quantum = Decimal(1).scaleb(-scale)
        decimal = decimal.quantize(quantum, rounding=ROUND_HALF_UP)
    return decimal


def _to_date(value: Any) -> dt.date:
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    return _to_datetime(value).date()


def _to_datetime(value: Any) -> dt.datetime:
    if isinstance(value, dt.datetime):
        return value
    if isinstance(value, dt.date):
        return dt.datetime(value.year, value.month, value.day)
    text = str(value).strip().replace("Z", "+00:00")
    try:
        return dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("Value is not an ISO-8601 date or datetime") from exc


def _parse_bool(text: str) -> bool:
    lowered = text.strip().lower()
    if lowered in ("1", "t", "true", "y", "yes", "on"):
        return True
    if lowered in ("0", "f", "false", "n", "no", "off", ""):
        return False
    raise ValueError("Value is not a boolean")


def type_repr(sa_type: Any) -> str:
    """Human-readable type name, used in reports and validation messages."""
    if isinstance(sa_type, TypeEngine):
        try:
            return str(sa_type)
        except Exception:  # pragma: no cover - exotic user-defined types
            return type(sa_type).__name__
    return str(sa_type)

"""Value coercion: everything a transformer returns passes through here."""

from __future__ import annotations

import datetime as dt
from decimal import Decimal

import pytest
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
    Text,
    Time,
)

from masker.errors import TransformerError
from masker.values import coerce, fit_value, sql_kind, type_repr


# --------------------------------------------------------------------------- #
# sql_kind
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("sa_type", "kind"),
    [
        (DateTime(), "datetime"),
        (Date(), "date"),
        (Time(), "time"),
        (Integer(), "integer"),
        (BigInteger(), "integer"),
        (SmallInteger(), "integer"),
        (Numeric(10, 2), "numeric"),
        (Float(), "float"),
        (Boolean(), "boolean"),
        (LargeBinary(), "binary"),
        (JSON(), "json"),
        (String(10), "string"),
        (Text(), "string"),
        (object(), "unknown"),
    ],
)
def test_sql_kind(sa_type: object, kind: str) -> None:
    assert sql_kind(sa_type) == kind


def test_datetime_is_not_reported_as_a_date() -> None:
    # DateTime subclasses Date, so the order of the checks matters.
    assert sql_kind(DateTime()) == "datetime"
    assert sql_kind(Date()) == "date"


# --------------------------------------------------------------------------- #
# fit_value
# --------------------------------------------------------------------------- #
def test_none_is_always_none() -> None:
    assert fit_value(None, String(10)) is None
    assert fit_value(None, Integer()) is None


def test_strings_are_truncated_to_the_column_length() -> None:
    assert fit_value("abcdefghij", String(4)) == "abcd"
    assert fit_value("abc", String(10)) == "abc"
    assert fit_value("abcdefghij", String(4), length=2) == "ab"


def test_unbounded_text_is_left_alone() -> None:
    assert fit_value("x" * 500, Text()) == "x" * 500


def test_non_strings_are_stringified_into_text_columns() -> None:
    assert fit_value(42, String(10)) == "42"
    assert fit_value(dt.date(2026, 1, 2), String(20)) == "2026-01-02"
    assert fit_value(dt.datetime(2026, 1, 2, 3, 4, 5), String(30)) == "2026-01-02 03:04:05"
    assert fit_value(Decimal("1.50"), String(10)) == "1.50"
    assert fit_value(dt.time(3, 4, 5), String(10)) == "03:04:05"


def test_integers_are_coerced() -> None:
    assert fit_value("42", Integer()) == 42
    assert fit_value(42.0, Integer()) == 42
    assert fit_value(Decimal("42"), Integer()) == 42
    assert fit_value(True, Integer()) == 1


def test_a_fractional_value_does_not_fit_an_integer_column() -> None:
    with pytest.raises(TransformerError, match="does not fit the integer column type"):
        fit_value(42.5, Integer())


def test_a_non_numeric_string_does_not_fit_an_integer_column() -> None:
    with pytest.raises(TransformerError, match="does not fit the integer column type"):
        fit_value("abc", Integer())


def test_numerics_honour_the_scale() -> None:
    assert fit_value("1.005", Numeric(10, 2)) == Decimal("1.01")
    assert fit_value(3, Numeric(10, 2)) == Decimal("3.00")
    assert fit_value(Decimal("2.5"), Numeric(10, 0)) == Decimal("3")  # ROUND_HALF_UP


def test_a_numeric_without_a_scale_keeps_its_value() -> None:
    assert fit_value(Decimal("1.23456"), Numeric()) == Decimal("1.23456")


def test_a_non_numeric_value_does_not_fit_a_numeric_column() -> None:
    with pytest.raises(TransformerError, match="does not fit the numeric column type"):
        fit_value("not a number", Numeric(10, 2))


def test_floats() -> None:
    assert fit_value("1.5", Float()) == 1.5
    assert fit_value(2, Float()) == 2.0


def test_booleans_accept_the_common_spellings() -> None:
    assert fit_value("yes", Boolean()) is True
    assert fit_value("off", Boolean()) is False
    assert fit_value(1, Boolean()) is True
    assert fit_value(0.0, Boolean()) is False
    assert fit_value(True, Boolean()) is True


def test_an_unparsable_boolean_is_refused() -> None:
    with pytest.raises(TransformerError, match="does not fit the boolean column type"):
        fit_value("maybe", Boolean())


def test_dates_and_datetimes() -> None:
    assert fit_value("2026-01-02", Date()) == dt.date(2026, 1, 2)
    assert fit_value(dt.datetime(2026, 1, 2, 3, 4), Date()) == dt.date(2026, 1, 2)
    assert fit_value(dt.date(2026, 1, 2), DateTime()) == dt.datetime(2026, 1, 2)
    assert fit_value("2026-01-02T03:04:05", DateTime()) == dt.datetime(2026, 1, 2, 3, 4, 5)
    assert fit_value("2026-01-02 03:04:05Z", DateTime()) == dt.datetime(
        2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc
    )


def test_an_unparsable_date_is_refused() -> None:
    with pytest.raises(TransformerError, match="does not fit the date column type"):
        fit_value("15/01/2026", Date())


def test_times() -> None:
    assert fit_value("03:04:05", Time()) == dt.time(3, 4, 5)
    assert fit_value(dt.datetime(2026, 1, 2, 3, 4, 5), Time()) == dt.time(3, 4, 5)
    assert fit_value(dt.time(3, 4, 5), Time()) == dt.time(3, 4, 5)


def test_an_unparsable_time_is_refused() -> None:
    with pytest.raises(TransformerError, match="does not fit the time column type"):
        fit_value("quarter past three", Time())


def test_binary_columns() -> None:
    assert fit_value(b"raw", LargeBinary()) == b"raw"
    assert fit_value(bytearray(b"raw"), LargeBinary()) == bytearray(b"raw")
    assert fit_value("text", LargeBinary()) == b"text"


def test_unknown_types_pass_through() -> None:
    sentinel = object()
    assert fit_value(sentinel, object()) is sentinel


def test_json_passes_through() -> None:
    assert fit_value({"a": 1}, JSON()) == {"a": 1}


# --------------------------------------------------------------------------- #
# coerce
# --------------------------------------------------------------------------- #
def test_coerce_none() -> None:
    assert coerce(None, int) is None


def test_coerce_int_from_strings() -> None:
    assert coerce(" 42 ", int) == 42


def test_coerce_bool_from_strings() -> None:
    assert coerce("TRUE", bool) is True
    assert coerce("", bool) is False


def test_coerce_to_str() -> None:
    assert coerce(Decimal("1.5"), str) == "1.5"


def test_coerce_to_an_unsupported_type_is_refused() -> None:
    with pytest.raises(TransformerError, match="No coercion rule"):
        coerce("x", complex)  # type: ignore[type-abstract]


def test_coerce_float() -> None:
    assert coerce("1.5", float) == 1.5


def test_type_repr_is_readable() -> None:
    assert type_repr(String(10)) == "VARCHAR(10)"
    assert type_repr("not-a-type") == "not-a-type"
    assert type_repr(Integer()) == "INTEGER"

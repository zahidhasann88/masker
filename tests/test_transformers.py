"""Unit tests for every transformer.

Covers the guarantees Masker advertises: determinism, format preservation,
length limits, NULL handling and unique-retry behaviour.
"""

from __future__ import annotations

import datetime as dt
import random
from collections.abc import Mapping
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy.types import (
    BigInteger,
    Date,
    DateTime,
    Integer,
    NullType,
    Numeric,
    String,
    Text,
)

from masker.errors import TransformerError, UniquenessError
from masker.keys import SecretKey
from masker.transformers import REGISTRY, build, names
from masker.transformers.base import BaseParams, BaseTransformer, ColumnContext
from masker.transformers.registry import TransformerRegistry

KEY = SecretKey.from_text("transformer-test-key-0123456789", origin="test")
OTHER = SecretKey.from_text("another-test-key-abcdef0123456789", origin="test")


def context(
    column: str = "col",
    *,
    table: str = "users",
    sa_type: Any = None,
    unique: bool = False,
    key: SecretKey = KEY,
    namespace: str = "",
    null_passthrough: bool = True,
    max_unique_attempts: int = 50,
) -> ColumnContext:
    resolved = String(50) if sa_type is None else sa_type
    return ColumnContext(
        table=table,
        column=column,
        key=key,
        sa_type=resolved,
        length=getattr(resolved, "length", None),
        is_unique=unique,
        namespace=namespace,
        null_passthrough=null_passthrough,
        max_unique_attempts=max_unique_attempts,
    )


def make(name: str, params: Mapping[str, Any] | None = None, **kwargs: Any) -> BaseTransformer[Any]:
    return build(name, dict(params or {}), context(**kwargs))


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
def test_every_documented_transformer_is_registered() -> None:
    expected = {
        "constant",
        "date_shift",
        "email",
        "fake",
        "hash",
        "keep",
        "null",
        "number_noise",
        "partial_mask",
        "preserve_format",
        "redact",
        "regex_replace",
        "shuffle",
    }
    assert expected <= set(names())


def test_unknown_transformer_names_the_available_ones() -> None:
    with pytest.raises(TransformerError, match="Unknown transformer: 'nope'"):
        make("nope")


def test_unknown_params_are_rejected() -> None:
    with pytest.raises(TransformerError, match="Invalid params"):
        make("hash", {"lenght": 4})


def test_duplicate_registration_is_rejected() -> None:
    registry = TransformerRegistry()

    class First(BaseTransformer[None]):  # type: ignore[type-arg]
        name = "dup"

        def _apply(self, value: Any, attempt: int) -> Any:
            return value

    registry.register(First)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="Duplicate transformer name"):
        registry.register(First)  # type: ignore[arg-type]


def test_registration_without_a_name_is_rejected() -> None:
    registry = TransformerRegistry()

    class Anonymous(BaseTransformer[None]):  # type: ignore[type-arg]
        def _apply(self, value: Any, attempt: int) -> Any:
            return value

    with pytest.raises(ValueError, match="does not define a 'name'"):
        registry.register(Anonymous)  # type: ignore[arg-type]


def test_describe_shows_non_default_params_only() -> None:
    assert make("email").describe() == "email"
    assert make("hash", {"length": 20}).describe() == "hash(length=20)"


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("name", "params", "value"),
    [
        ("fake", {"provider": "name"}, "Jane Doe"),
        ("hash", {"length": 10}, "ssn-1"),
        ("partial_mask", {"keep_last": 4}, "555-0100"),
        ("preserve_format", {}, "555-0100"),
        ("regex_replace", {"pattern": r"\d", "replacement": "X"}, "a1b2"),
        ("date_shift", {"min_days": -30, "max_days": 30}, dt.date(1990, 5, 5)),
        ("number_noise", {"percent": 10}, 12345),
        ("email", {}, "jane.doe+news@corp.example"),
        ("email", {"style": "hash"}, "jane@corp.example"),
        ("redact", {}, "secret"),
        ("constant", {"value": "x"}, "secret"),
    ],
)
def test_same_key_same_output(name: str, params: dict[str, Any], value: Any) -> None:
    assert make(name, params)(value) == make(name, params)(value)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("hash", "jane@corp.example"),
        ("email", "jane@corp.example"),
        ("preserve_format", "jane@corp.example"),
        ("date_shift", dt.date(1990, 4, 4)),
        ("number_noise", 123456),
    ],
)
def test_different_keys_give_different_output(name: str, value: Any) -> None:
    plain = make(name, {}, key=KEY, column="email")
    rekeyed = make(name, {}, key=OTHER, column="email")
    assert plain(value) != rekeyed(value)


def test_column_is_part_of_the_digest_namespace() -> None:
    first = make("hash", column="email")
    second = make("hash", column="other")
    assert first("jane@corp.example") != second("jane@corp.example")


def test_namespace_override_links_columns_across_tables() -> None:
    primary = make("hash", column="id", table="users", namespace="users.id")
    foreign = make("hash", column="user_id", table="orders", namespace="users.id")
    assert primary(42) == foreign(42)


def test_same_table_column_without_namespace_stays_separate() -> None:
    primary = make("hash", column="id", table="users")
    foreign = make("hash", column="user_id", table="orders")
    assert primary(42) != foreign(42)


# --------------------------------------------------------------------------- #
# NULL handling
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", ["email", "hash", "fake", "preserve_format", "date_shift"])
def test_null_passes_through_by_default(name: str) -> None:
    params = {"provider": "name"} if name == "fake" else {}
    assert make(name, params)(None) is None


def test_null_can_be_transformed_when_configured() -> None:
    transformer = make("constant", {"value": "n/a"}, null_passthrough=False)
    assert transformer(None) == "n/a"


def test_transformers_that_need_a_value_raise_on_null() -> None:
    transformer = make("email", {}, null_passthrough=False)
    with pytest.raises(TransformerError, match="received NULL"):
        transformer(None)


# --------------------------------------------------------------------------- #
# Fitting: types and lengths
# --------------------------------------------------------------------------- #
def test_output_is_truncated_to_the_column_length() -> None:
    transformer = make("fake", {"provider": "name"}, sa_type=String(8))
    assert len(transformer("Jane Doe")) <= 8


def test_text_is_preserved_verbatim() -> None:
    transformer = make("hash", {"length": 40}, sa_type=Text())
    assert len(transformer("value")) == 40


def test_date_column_returns_a_date() -> None:
    transformer = make("date_shift", {"min_days": -5, "max_days": 5}, sa_type=Date())
    assert isinstance(transformer(dt.date(2000, 1, 1)), dt.date)


def test_datetime_column_returns_a_datetime() -> None:
    transformer = make("date_shift", {}, sa_type=DateTime())
    assert isinstance(transformer(dt.datetime(2000, 1, 1)), dt.datetime)


def test_numeric_column_is_rounded_to_its_scale() -> None:
    transformer = make("number_noise", {"percent": 25}, sa_type=Numeric(10, 2))
    result = transformer(Decimal("19.99"))
    assert isinstance(result, Decimal)
    assert -result.as_tuple().exponent == 2


def test_integer_column_rejects_a_text_transformer() -> None:
    transformer = make("hash", {"as_number": False}, sa_type=Integer())
    with pytest.raises(TransformerError, match="does not fit the integer column type"):
        transformer(42)


# --------------------------------------------------------------------------- #
# fake
# --------------------------------------------------------------------------- #
def test_fake_rejects_an_unknown_provider_with_a_suggestion() -> None:
    with pytest.raises(TransformerError, match="Unknown Faker provider"):
        make("fake", {"provider": "nmae"})


def test_fake_rejects_an_unknown_locale() -> None:
    with pytest.raises(TransformerError, match="Unknown Faker locale"):
        make("fake", {"provider": "name", "locale": "xx_YY"})


def test_fake_honours_the_locale() -> None:
    german = make("fake", {"provider": "city", "locale": "de_DE"})
    assert german("Berlin") != make("fake", {"provider": "city"})("Berlin")


def test_fake_passes_args_and_kwargs() -> None:
    transformer = make("fake", {"provider": "random_int", "args": [5, 6]}, sa_type=Integer())
    assert transformer(1) in (5, 6)


# --------------------------------------------------------------------------- #
# hash
# --------------------------------------------------------------------------- #
def test_hash_length_and_prefix() -> None:
    assert make("hash", {"length": 8, "prefix": "ID-"})("value") == make(
        "hash", {"length": 8, "prefix": "ID-"}
    )("value")
    result = make("hash", {"length": 8, "prefix": "ID-"})("value")
    assert result.startswith("ID-")
    assert len(result) == 11


def test_hash_uppercase() -> None:
    assert make("hash", {"uppercase": True})("v") == make("hash", {"uppercase": True})("v").upper()


def test_hash_on_an_integer_column_stays_an_integer() -> None:
    transformer = make("hash", sa_type=Integer())
    result = transformer(42)
    assert isinstance(result, int)
    assert 0 <= result < 2**31


def test_hash_on_a_bigint_column_uses_a_wider_range() -> None:
    small = make("hash", sa_type=Integer())(12345)
    wide = make("hash", sa_type=BigInteger())(12345)
    assert isinstance(wide, int)
    assert wide >= 0
    assert small != wide


def test_hash_as_number_on_a_text_column_is_rejected() -> None:
    with pytest.raises(TransformerError, match="needs an integer column"):
        make("hash", {"as_number": True}, sa_type=String(10))


def test_hash_prefix_with_a_number_is_rejected() -> None:
    with pytest.raises(TransformerError, match="cannot add the prefix"):
        make("hash", {"prefix": "X"}, sa_type=Integer())


# --------------------------------------------------------------------------- #
# partial_mask
# --------------------------------------------------------------------------- #
def test_partial_mask_keeps_the_requested_ends() -> None:
    assert make("partial_mask", {"keep_last": 4})("4111111111111111") == "************1111"


def test_partial_mask_keeps_the_length() -> None:
    value = "555-0142"
    assert len(make("partial_mask", {"keep_first": 3})(value)) == len(value)


def test_partial_mask_hides_everything_when_there_is_nothing_to_mask() -> None:
    assert make("partial_mask", {"keep_last": 20})("abc") == "***"


# --------------------------------------------------------------------------- #
# preserve_format
# --------------------------------------------------------------------------- #
def test_preserve_format_keeps_length_and_character_classes() -> None:
    result = make("preserve_format")("555-01AB")
    assert len(result) == len("555-01AB")
    for original, masked in zip("555-01AB", result, strict=True):
        if original.isdigit():
            assert masked.isdigit()
        elif original.islower():
            assert masked.islower()
        elif original.isupper():
            assert masked.isupper()
        else:
            assert masked == original


def test_preserve_format_can_keep_leading_positions() -> None:
    result = make("preserve_format", {"keep_positions": 2})("10.0.0.1")
    assert result.startswith("10.")


# --------------------------------------------------------------------------- #
# date_shift
# --------------------------------------------------------------------------- #
def test_date_shift_stays_inside_the_bounds() -> None:
    original = dt.date(2000, 6, 15)
    transformer = make("date_shift", {"min_days": -30, "max_days": 30}, sa_type=Date())
    for _ in range(20):
        shifted = transformer(original)
        assert isinstance(shifted, dt.date)
        assert abs((shifted - original).days) <= 30


def test_date_shift_is_stable_for_the_same_input() -> None:
    transformer = make("date_shift", {}, sa_type=Date())
    assert transformer(dt.date(1999, 1, 1)) == transformer(dt.date(1999, 1, 1))


def test_date_shift_handles_iso_strings() -> None:
    transformer = make("date_shift", {"min_days": -1, "max_days": 1}, sa_type=String(10))
    result = transformer("1999-01-01")
    assert isinstance(result, str)
    assert len(result) == 10


def test_date_shift_clamps_to_the_requested_window() -> None:
    transformer = make(
        "date_shift",
        {"min_days": -10_000, "max_days": 10_000, "clamp_min": "2000-01-01"},
        sa_type=Date(),
    )
    result = transformer(dt.date(1900, 1, 1))
    assert result == dt.date(2000, 1, 1)


def test_date_shift_rejects_inverted_bounds() -> None:
    with pytest.raises(TransformerError, match="must not exceed"):
        make("date_shift", {"min_days": 10, "max_days": -10})


def test_date_shift_rejects_a_value_it_cannot_handle() -> None:
    transformer = make("date_shift", {}, sa_type=String(20))
    with pytest.raises(TransformerError, match="cannot handle"):
        transformer({"not": "a date"})


# --------------------------------------------------------------------------- #
# number_noise
# --------------------------------------------------------------------------- #
def test_number_noise_percent_stays_in_range() -> None:
    transformer = make("number_noise", {"percent": 10}, sa_type=Numeric(10, 2))
    result = transformer(1000)
    assert 900 <= float(result) <= 1100


def test_number_noise_absolute_bounds() -> None:
    transformer = make("number_noise", {"min_delta": -3, "max_delta": 3}, sa_type=Integer())
    result = transformer(100)
    assert isinstance(result, int)
    assert 97 <= result <= 103


def test_number_noise_swaps_inverted_bounds() -> None:
    transformer = make("number_noise", {"min_delta": 5, "max_delta": -5}, sa_type=Integer())
    assert 95 <= transformer(100) <= 105


def test_number_noise_defaults_to_ten_percent() -> None:
    transformer = make("number_noise", {}, sa_type=Numeric(10, 2))
    assert 90 <= float(transformer(100)) <= 110


def test_number_noise_rejects_booleans() -> None:
    with pytest.raises(TransformerError, match="does not apply"):
        make("number_noise", {}, sa_type=Integer())(True)


def test_number_noise_rejects_non_numeric_text() -> None:
    transformer = make("number_noise", {}, sa_type=Numeric(10, 2))
    with pytest.raises(TransformerError, match="cannot parse"):
        transformer("not a number")


def test_number_noise_rejects_unsupported_types() -> None:
    transformer = make("number_noise", {}, sa_type=Numeric(10, 2))
    with pytest.raises(TransformerError, match="cannot handle"):
        transformer({"a": 1})


def test_number_noise_accepts_numeric_strings() -> None:
    transformer = make("number_noise", {"percent": 0}, sa_type=Numeric(10, 2))
    assert transformer("12.50") == Decimal("12.50")


# --------------------------------------------------------------------------- #
# email
# --------------------------------------------------------------------------- #
def test_email_uses_the_safe_domain_and_keeps_the_structure() -> None:
    result = make("email")("jane.doe+news@corp.example")
    local, _, domain = result.partition("@")
    assert domain == "example.test"
    assert local.count(".") == 1
    assert "+news" not in local
    assert local.split("+")[0] != "jane.doe"


def test_email_can_keep_the_original_domain() -> None:
    result = make("email", {"keep_domain": True})("jane@corp.example")
    assert result.endswith("@corp.example")


def test_email_hash_style() -> None:
    result = make("email", {"style": "hash"})("jane@corp.example")
    assert result == make("email", {"style": "hash"})("jane@corp.example")
    assert result.endswith("@example.test")


def test_email_handles_a_value_without_an_at_sign() -> None:
    assert make("email")("not-an-email").endswith("@example.test")


def test_email_suffix_can_be_disabled() -> None:
    result = make("email", {"suffix_digits": 0})("jane@corp.example")
    local, _, _ = result.partition("@")
    assert local.isalpha()


# --------------------------------------------------------------------------- #
# regex_replace / redact / constant / null / keep
# --------------------------------------------------------------------------- #
def test_regex_replace_supports_backreferences() -> None:
    transformer = make("regex_replace", {"pattern": r"(\w+)@(\w+)", "replacement": r"\2/\1"})
    assert transformer("a@b") == "b/a"


def test_regex_replace_respects_count() -> None:
    transformer = make("regex_replace", {"pattern": "a", "replacement": "b", "count": 1})
    assert transformer("aaa") == "baa"


def test_regex_replace_rejects_an_invalid_pattern() -> None:
    with pytest.raises(TransformerError, match="Invalid regex"):
        make("regex_replace", {"pattern": "([", "replacement": "x"})


def test_regex_replace_rejects_an_invalid_replacement() -> None:
    # A bad backreference only surfaces when a match exists, so it is reported
    # when the value is masked rather than when the rules are loaded.
    transformer = make("regex_replace", {"pattern": "a", "replacement": r"\g<nope>"})
    with pytest.raises(TransformerError, match="Invalid replacement"):
        transformer("a")


def test_regex_replace_ignores_case_when_asked() -> None:
    transformer = make("regex_replace", {"pattern": "abc", "replacement": "X", "ignore_case": True})
    assert transformer("ABC") == "X"


def test_regex_replace_adds_a_suffix_on_uniqueness_retry() -> None:
    transformer = make(
        "regex_replace",
        {"pattern": r"\d", "replacement": "0"},
        sa_type=String(40),
        unique=True,
    )
    first, second = transformer("a1"), transformer("a2")
    assert first != second


def test_redact_replaces_every_value() -> None:
    transformer = make("redact")
    assert transformer("a") == "[REDACTED]"
    assert transformer("b") == "[REDACTED]"


def test_redact_accepts_a_custom_marker() -> None:
    assert make("redact", {"value": "gone"})("a") == "gone"


def test_constant_replaces_every_value() -> None:
    assert make("constant", {"value": 0}, sa_type=Integer())("a") == 0
    assert make("constant", {"value": 0})("a") == "0"  # fitted to the text column


def test_null_always_returns_none() -> None:
    assert make("null")("a") is None


def test_keep_returns_the_value_unchanged() -> None:
    assert make("keep")("a") == "a"


# --------------------------------------------------------------------------- #
# shuffle
# --------------------------------------------------------------------------- #
def test_shuffle_is_a_reproducible_bijection() -> None:
    values = [f"user{i}@corp.example" for i in range(25)]
    first, second = make("shuffle"), make("shuffle")
    first.prepare(values)
    second.prepare(values)
    mapped = [first(value) for value in values]
    assert sorted(mapped) == sorted(values)
    assert [second(value) for value in values] == mapped


def test_shuffle_needs_a_prepass_and_never_leaks_an_unseen_value() -> None:
    transformer = make("shuffle")
    transformer.prepare(["a@x.test", "b@x.test"])
    assert transformer("a@x.test") != "a@x.test"
    with pytest.raises(TransformerError, match="source changed"):
        transformer("unseen@x.test")
    assert transformer.unmapped == 1


def test_shuffle_skips_nulls_during_the_prepass() -> None:
    transformer = make("shuffle")
    transformer.prepare([None, "a@x.test", "b@x.test"])
    assert transformer.distinct_values_seen == 2


def test_shuffle_rejects_unhashable_values() -> None:
    transformer = make("shuffle")
    transformer.prepare([])
    with pytest.raises(TransformerError, match="hashable"):
        transformer({"json": True})


def test_shuffle_output_differs_between_columns() -> None:
    first, second = make("shuffle", column="a"), make("shuffle", column="b")
    values = list("abcdefghij")
    first.prepare(values)
    second.prepare(values)
    assert [first(v) for v in values] != [second(v) for v in values]


# --------------------------------------------------------------------------- #
# Uniqueness
# --------------------------------------------------------------------------- #
def test_unique_column_retries_until_the_value_is_unique() -> None:
    transformer = make("partial_mask", {"keep_last": 2}, sa_type=String(10), unique=True)
    results = [transformer(value) for value in ["ab", "ac", "ad", "ae", "af"]]
    assert len(set(results)) == len(results)
    assert transformer.retries > 0


def test_unique_transformer_gives_up_with_a_clear_error() -> None:
    class AlwaysTheSame(BaseTransformer[BaseParams]):
        name = "always-the-same"
        params_model = BaseParams

        def _apply(self, value: Any, attempt: int) -> Any:
            return "constant-output"

    registry = TransformerRegistry()
    registry.register(AlwaysTheSame)  # type: ignore[arg-type]
    transformer = registry.build("always-the-same", {}, context(unique=True, max_unique_attempts=4))
    assert transformer("first") == "constant-output"
    with pytest.raises(UniquenessError, match="could not produce a unique value"):
        transformer("second")


def test_nulls_do_not_count_towards_uniqueness() -> None:
    transformer = make("email", {}, sa_type=String(60), unique=True)
    assert transformer(None) is None
    assert transformer(None) is None


def test_a_constant_transformer_cannot_be_used_on_a_unique_column() -> None:
    with pytest.raises(TransformerError, match="UNIQUE constraint"):
        make("redact", {}, unique=True)
    with pytest.raises(TransformerError, match="UNIQUE constraint"):
        make("constant", {"value": 1}, unique=True)


def test_null_is_allowed_on_a_unique_column() -> None:
    assert make("null", {}, unique=True)("x") is None


def test_unhashable_values_are_tracked_by_their_repr() -> None:
    class Unhashable:
        def __init__(self, tag: str) -> None:
            self.tag = tag

        def __repr__(self) -> str:
            return f"Unhashable({self.tag})"

        def __hash__(self) -> int:
            raise TypeError

    class PassThrough(BaseTransformer[BaseParams]):
        name = "pass-through"
        params_model = BaseParams

        def _apply(self, value: Any, attempt: int) -> Any:
            return value

    registry = TransformerRegistry()
    registry.register(PassThrough)  # type: ignore[arg-type]
    # NullType has no length and no coercion, so the object survives fitting.
    transformer = registry.build(
        "pass-through", {}, context(unique=True, sa_type=NullType(), max_unique_attempts=3)
    )
    assert transformer(Unhashable("a")) is not None
    assert transformer(Unhashable("b")) is not None
    assert transformer(Unhashable("a")) is transformer(Unhashable("a"))


# --------------------------------------------------------------------------- #
# Randomness plumbing
# --------------------------------------------------------------------------- #
def test_rng_stream_is_reproducible() -> None:
    first = context().rng("value")
    second = context().rng("value")
    assert [first.random() for _ in range(5)] == [second.random() for _ in range(5)]


def test_int_digest_rejects_a_bad_width() -> None:
    with pytest.raises(ValueError, match="n_bytes"):
        KEY.int_digest("a", n_bytes=0)


def test_digest_accepts_bytes_and_ints() -> None:
    ctx = context()
    assert ctx.digest("a", 1, b"raw") == ctx.digest("a", 1, b"raw")


def test_registry_lists_every_transformer_in_alphabetical_order() -> None:
    assert REGISTRY.names() == sorted(REGISTRY.names())


def test_random_seed_helper_is_available() -> None:
    """Determinism relies on a stable PRNG, so pin the property we depend on."""
    seeded = random.Random(1234)
    assert round(seeded.random(), 6) == round(random.Random(1234).random(), 6)

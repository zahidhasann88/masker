"""``fake`` -- replace a value with a realistic one from a Faker provider.

```yaml
columns:
  first_name: {transformer: fake, params: {provider: first_name}}
  city:       {transformer: fake, params: {provider: city, locale: de_DE}}
  birthday:   {transformer: fake, params: {provider: date_of_birth}}
```
"""

from __future__ import annotations

import difflib
from collections.abc import Mapping
from typing import Any

from faker import Faker

from masker.errors import TransformerError
from masker.transformers.base import BaseParams, BaseTransformer, ColumnContext
from masker.transformers.registry import register

__all__ = ["FakeParams", "FakeTransformer", "get_faker"]

_FAKERS: dict[str, Faker] = {}


def get_faker(locale: str) -> Faker:
    """A cached Faker instance per locale. Seeded per call by the transformer."""
    cached = _FAKERS.get(locale)
    if cached is None:
        try:
            cached = Faker(locale)
        except Exception as exc:  # Faker raises AttributeError for unknown locales
            raise TransformerError(
                f"Unknown Faker locale: {locale!r}",
                hint="Use a locale such as en_US, en_GB or de_DE (see Faker's docs).",
            ) from exc
        _FAKERS[locale] = cached
    return cached


class FakeParams(BaseParams):
    provider: str
    locale: str | None = None
    args: list[Any] = []
    kwargs: dict[str, Any] = {}


@register
class FakeTransformer(BaseTransformer[FakeParams]):
    name = "fake"
    summary = "Realistic replacement value from a named Faker provider."
    params_model = FakeParams

    def __init__(self, params: Mapping[str, Any] | None, ctx: ColumnContext) -> None:
        super().__init__(params, ctx)
        locale = self.params.locale or ctx.locale or "en_US"
        faker = get_faker(locale)
        provider = getattr(faker, self.params.provider, None)
        if not callable(provider):
            close = difflib.get_close_matches(self.params.provider, dir(faker), n=3)
            suggestion = f" Did you mean: {', '.join(close)}?" if close else ""
            raise TransformerError(
                f"Unknown Faker provider {self.params.provider!r} for locale {locale!r}."
                f"{suggestion}",
                hint="Provider names come from Faker, for example name, first_name, "
                "company, city, iban, ssn.",
            )
        self._provider = provider

    def _apply(self, value: Any, attempt: int) -> Any:
        self.require_not_null(value)
        locale = self.params.locale or self.ctx.locale or "en_US"
        seed = self.ctx.int_digest(_stable(value), attempt, n_bytes=8)
        get_faker(locale).seed_instance(seed)
        return self._provider(*self.params.args, **self.params.kwargs)


def _stable(value: Any) -> str:
    return value if isinstance(value, str) else repr(value)

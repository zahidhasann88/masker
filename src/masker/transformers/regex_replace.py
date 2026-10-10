"""``regex_replace`` -- surgical rewrite of part of a value.

```yaml
columns:
  # Turn "https://cdn.example.com/u/8812/avatar.png" into a stable fake path.
  avatar_url: {transformer: regex_replace, params: {pattern: "/u/\\d+/", replacement: "/u/0/"}}
  postcode:   {transformer: regex_replace, params: {pattern: "\\d", replacement: "0"}}
```

Backreferences (``\\1``) work in ``replacement``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from masker.errors import TransformerError
from masker.transformers.base import BaseParams, BaseTransformer, ColumnContext
from masker.transformers.registry import register

__all__ = ["RegexReplaceParams", "RegexReplaceTransformer"]


class RegexReplaceParams(BaseParams):
    pattern: str
    replacement: str
    count: int = 0
    ignore_case: bool = False


@register
class RegexReplaceTransformer(BaseTransformer[RegexReplaceParams]):
    name = "regex_replace"
    summary = "Rewrite the parts of a value that match a regex."
    params_model = RegexReplaceParams

    def __init__(self, params: Mapping[str, Any] | None, ctx: ColumnContext) -> None:
        super().__init__(params, ctx)
        flags = re.IGNORECASE if self.params.ignore_case else 0
        try:
            self._pattern = re.compile(self.params.pattern, flags)
        except re.error as exc:
            raise TransformerError(
                f"Invalid regex {self.params.pattern!r} on {ctx.qualified}: {exc}"
            ) from exc

    def _apply(self, value: Any, attempt: int) -> Any:
        text = str(self.require_not_null(value))
        if attempt:
            # Uniqueness retry: append a keyed suffix so repeats differ.
            suffix = self.ctx.hex_digest(text, attempt, length=4)
            return f"{self._sub(text)}-{suffix}"
        return self._sub(text)

    def _sub(self, text: str) -> str:
        try:
            return self._pattern.sub(self.params.replacement, text, count=self.params.count)
        except (re.error, IndexError, KeyError) as exc:
            # A bad backreference only surfaces once a match exists, and the
            # exception type differs between Python versions.
            raise TransformerError(
                f"Invalid replacement {self.params.replacement!r} on {self.ctx.qualified}: {exc}"
            ) from exc

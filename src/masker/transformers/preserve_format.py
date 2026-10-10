"""``preserve_format`` -- same length, same character classes, new content.

Digits stay digits, uppercase stays uppercase, lowercase stays lowercase, and
everything else (spaces, dashes, slashes) is kept verbatim:

```yaml
columns:
  phone:    {transformer: preserve_format}   # "555-0142" -> "831-7760"
  postcode: {transformer: preserve_format}   # "SW1A 1AA" -> "KR4T 7QM"
  ip:       {transformer: preserve_format}   # "10.0.0.1"  -> "72.5.3.9"
```
"""

from __future__ import annotations

import string
from typing import Any

from masker.transformers.base import BaseParams, BaseTransformer
from masker.transformers.registry import register

__all__ = ["PreserveFormatParams", "PreserveFormatTransformer"]

_DIGITS = string.digits
_LOWER = string.ascii_lowercase
_UPPER = string.ascii_uppercase


class PreserveFormatParams(BaseParams):
    #: Number of leading characters copied verbatim (default: none).
    keep_positions: int = 0


@register
class PreserveFormatTransformer(BaseTransformer[PreserveFormatParams]):
    name = "preserve_format"
    summary = "Keep the length and character classes, replace the content."
    params_model = PreserveFormatParams

    def _apply(self, value: Any, attempt: int) -> Any:
        text = str(self.require_not_null(value))
        rng = self.ctx.rng(text, attempt)
        keep = max(self.params.keep_positions, 0)
        out: list[str] = []
        for index, char in enumerate(text):
            if index < keep:
                out.append(char)
            elif char.isdigit():
                out.append(rng.choice(_DIGITS))
            elif char.islower():
                out.append(rng.choice(_LOWER))
            elif char.isupper():
                out.append(rng.choice(_UPPER))
            else:
                out.append(char)
        return "".join(out)

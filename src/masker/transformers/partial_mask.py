"""``partial_mask`` -- keep the ends, mask the middle.

```yaml
columns:
  card_number: {transformer: partial_mask, params: {keep_last: 4}}
  phone:       {transformer: partial_mask, params: {keep_first: 3, keep_last: 2}}
```

If ``keep_first + keep_last`` would leave nothing to mask, the whole value is
masked instead: silently emitting the original would be a leak.
"""

from __future__ import annotations

import string
from typing import Any

from masker.transformers.base import BaseParams, BaseTransformer
from masker.transformers.registry import register

__all__ = ["PartialMaskParams", "PartialMaskTransformer"]

_ALPHABET = string.ascii_lowercase + string.digits


class PartialMaskParams(BaseParams):
    keep_first: int = 0
    keep_last: int = 4
    mask_char: str = "*"


@register
class PartialMaskTransformer(BaseTransformer[PartialMaskParams]):
    name = "partial_mask"
    summary = "Keep the first/last N characters, mask the rest."
    params_model = PartialMaskParams

    def _apply(self, value: Any, attempt: int) -> Any:
        text = str(self.require_not_null(value))
        length = len(text)
        keep_first = min(max(self.params.keep_first, 0), length)
        keep_last = min(max(self.params.keep_last, 0), length - keep_first)

        if keep_first + keep_last >= length:
            # Nothing would be hidden, so hide everything.
            keep_first = keep_last = 0

        if attempt:
            # A uniqueness retry: fill the masked region with keyed filler
            # instead of a repeated mask character, so the result differs.
            rng = self.ctx.rng(text, attempt)
            filler = "".join(rng.choice(_ALPHABET) for _ in range(length - keep_first - keep_last))
        else:
            filler = self.params.mask_char * (length - keep_first - keep_last)

        return f"{text[:keep_first]}{filler}{text[length - keep_last :] if keep_last else ''}"

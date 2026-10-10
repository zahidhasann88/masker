"""``keep`` -- an explicit, reviewed decision to leave a column untouched.

```yaml
columns:
  created_at: {transformer: keep}   # reviewed: not PII
```

Functionally identical to having no rule at all, but it shows up in reports as
a deliberate choice rather than an omission, and ``masker scan`` stops listing
the column as unruled.
"""

from __future__ import annotations

from typing import Any, ClassVar

from masker.transformers.base import BaseParams, BaseTransformer
from masker.transformers.registry import register

__all__ = ["KeepParams", "KeepTransformer"]


class KeepParams(BaseParams):
    pass


@register
class KeepTransformer(BaseTransformer[KeepParams]):
    name = "keep"
    summary = "Copy the value through unchanged (an explicit decision)."
    params_model = KeepParams
    tracks_uniqueness: ClassVar[bool] = False

    def _apply(self, value: Any, attempt: int) -> Any:
        return value

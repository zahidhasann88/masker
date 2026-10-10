"""``redact`` -- replace with a constant marker string.

```yaml
columns:
  password_hash: {transformer: redact}
  ssn:           {transformer: redact, params: {value: "[removed]"}}
```
"""

from __future__ import annotations

from typing import Any, ClassVar

from masker.transformers.base import BaseParams, BaseTransformer
from masker.transformers.registry import register

__all__ = ["RedactParams", "RedactTransformer"]


class RedactParams(BaseParams):
    value: str = "[REDACTED]"


@register
class RedactTransformer(BaseTransformer[RedactParams]):
    name = "redact"
    summary = "Replace every value with a constant marker string."
    params_model = RedactParams
    supports_uniqueness: ClassVar[bool] = False
    tracks_uniqueness: ClassVar[bool] = False

    def _apply(self, value: Any, attempt: int) -> Any:
        return self.params.value

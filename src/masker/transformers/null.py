"""``null`` -- write NULL.

```yaml
columns:
  middle_name: {transformer: null}
```

A ``null`` transformer is allowed on a UNIQUE column: PostgreSQL, MySQL and
SQLite all permit multiple NULLs in a unique index.
"""

from __future__ import annotations

from typing import Any, ClassVar

from masker.transformers.base import BaseParams, BaseTransformer
from masker.transformers.registry import register

__all__ = ["NullParams", "NullTransformer"]


class NullParams(BaseParams):
    pass


@register
class NullTransformer(BaseTransformer[NullParams]):
    name = "null"
    summary = "Write NULL for every value."
    params_model = NullParams
    tracks_uniqueness: ClassVar[bool] = False

    def _apply(self, value: Any, attempt: int) -> Any:
        return None

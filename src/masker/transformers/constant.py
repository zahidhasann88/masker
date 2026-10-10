"""``constant`` -- replace with a fixed value you choose.

```yaml
columns:
  status:  {transformer: constant, params: {value: "inactive"}}
  balance: {transformer: constant, params: {value: 0}}
```
"""

from __future__ import annotations

from typing import Any, ClassVar

from masker.transformers.base import BaseParams, BaseTransformer
from masker.transformers.registry import register

__all__ = ["ConstantParams", "ConstantTransformer"]


class ConstantParams(BaseParams):
    value: Any = None


@register
class ConstantTransformer(BaseTransformer[ConstantParams]):
    name = "constant"
    summary = "Replace every value with one fixed value."
    params_model = ConstantParams
    supports_uniqueness: ClassVar[bool] = False
    tracks_uniqueness: ClassVar[bool] = False

    def _apply(self, value: Any, attempt: int) -> Any:
        return self.params.value

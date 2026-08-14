from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class ConstantClock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Tuple

from detection import Alert, NormalizedEvent


class BaseRule(ABC):
    @property
    @abstractmethod
    def rule_name(self) -> str:
        ...

    @abstractmethod
    def evaluate(
        self,
        events: List[NormalizedEvent],
        indexed: Dict[Tuple, List[NormalizedEvent]],
    ) -> List[Alert]:
        ...

"""
Base Rule Interface — all detection rules implement this.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Tuple

from detection import Alert, NormalizedEvent


class BaseRule(ABC):
    """Abstract base class for all detection rules."""

    @property
    @abstractmethod
    def rule_name(self) -> str:
        """Unique name for this rule."""
        ...

    @abstractmethod
    def evaluate(
        self,
        events: List[NormalizedEvent],
        indexed: Dict[Tuple, List[NormalizedEvent]],
    ) -> List[Alert]:
        """
        Evaluate the rule against the provided events.

        Args:
            events:  All normalized events, sorted by timestamp.
            indexed: Events pre-indexed by (source_ip, username) tuples.

        Returns:
            List of Alert objects fired by this rule.
        """
        ...

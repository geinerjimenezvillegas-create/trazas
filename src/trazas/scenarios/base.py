"""Scenario contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import ClassVar, Literal

from trazas.context import GenContext
from trazas.events import Event

Platform = Literal["windows", "linux"]


class Scenario(ABC):
    """An attack scenario that emits the malicious events of one technique chain.

    Benign background noise is added separately by the engine, so scenarios only
    need to describe what the attacker does.
    """

    id: ClassVar[str]
    name: ClassVar[str]
    description: ClassVar[str]
    platform: ClassVar[Platform]
    techniques: ClassVar[tuple[str, ...]]

    @abstractmethod
    def generate(self, ctx: GenContext) -> Iterator[Event]:
        """Yield the scenario's events. Order does not matter; the engine sorts."""

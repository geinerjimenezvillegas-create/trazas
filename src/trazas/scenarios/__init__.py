"""Scenario registry.

Scenarios are registered explicitly instead of discovered dynamically so that
running ``trazas`` never imports code from outside the package.
"""

from __future__ import annotations

from trazas.scenarios.base import Platform, Scenario
from trazas.scenarios.psexec_lateral import PsExecLateralMovement
from trazas.scenarios.ssh_bruteforce import SshBruteForce
from trazas.scenarios.windows_bruteforce import WindowsBruteForce
from trazas.scenarios.windows_spray import WindowsPasswordSpray

_ALL: tuple[type[Scenario], ...] = (
    WindowsBruteForce,
    WindowsPasswordSpray,
    PsExecLateralMovement,
    SshBruteForce,
)

REGISTRY: dict[str, type[Scenario]] = {cls.id: cls for cls in _ALL}

__all__ = ["REGISTRY", "Platform", "Scenario", "get"]


def get(scenario_id: str) -> Scenario:
    try:
        return REGISTRY[scenario_id]()
    except KeyError:
        known = ", ".join(sorted(REGISTRY))
        raise KeyError(f"unknown scenario {scenario_id!r}; available: {known}") from None

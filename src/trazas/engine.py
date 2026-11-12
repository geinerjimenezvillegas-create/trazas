"""Combine scenarios and noise into one time-ordered dataset."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from trazas import degrade as degradation
from trazas import scenarios
from trazas.context import GenContext
from trazas.degrade import FieldDegradation
from trazas.events import Event
from trazas.noise import noise_for

DEFAULT_WINDOW_S = 3600.0
MAX_NOISE = 1_000_000


def generate(
    scenario_ids: Sequence[str],
    *,
    seed: int,
    start: datetime,
    noise: int = 200,
    window_s: float = DEFAULT_WINDOW_S,
    degrade: Sequence[FieldDegradation] = (),
) -> list[Event]:
    """Generate a sorted list of events for the given scenarios.

    ``noise`` is the number of benign events per platform involved. ``degrade``
    drops or truncates fields afterwards to simulate incomplete telemetry.
    """
    if not scenario_ids:
        raise ValueError("at least one scenario is required")
    if not 0 <= noise <= MAX_NOISE:
        raise ValueError(f"noise must be between 0 and {MAX_NOISE}")
    if window_s <= 0:
        raise ValueError("window must be positive")

    ctx = GenContext(seed=seed, start=start)
    selected = [scenarios.get(sid) for sid in dict.fromkeys(scenario_ids)]

    events: list[Event] = []
    for scenario in selected:
        events.extend(scenario.generate(ctx))
    for platform in sorted({s.platform for s in selected}):
        events.extend(noise_for(platform, ctx, noise, window_s))

    # Stable sort: ties keep generation order, so output stays deterministic.
    events.sort(key=lambda e: e.timestamp)
    # Last, so the RNG draws for generation are the same with or without degradation.
    return degradation.apply(events, degrade, ctx)

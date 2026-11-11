"""Simulate incomplete telemetry by dropping or truncating fields.

Real pipelines lose data: collectors drop long fields, parsers fail, size limits cut
values. A rule that depends on one field can then miss an attack *silently*, which is
worse than a noisy false positive. Degradation is applied after generation, so the
rest of each event is exactly what the undegraded dataset would contain.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import Any

from trazas.context import GenContext
from trazas.events import Event

_FIELD_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


@dataclass(frozen=True, slots=True)
class FieldDegradation:
    """Degrade ``field`` in a ``ratio`` share of the events that carry it.

    With ``truncate_to`` unset the field is removed. Otherwise string values longer
    than ``truncate_to`` characters are cut to that length.
    """

    field: str
    ratio: float
    truncate_to: int | None = None

    def __post_init__(self) -> None:
        if not _FIELD_NAME.match(self.field):
            raise ValueError(f"invalid field name: {self.field!r}")
        if not 0 < self.ratio <= 1:  # also rejects NaN
            raise ValueError(f"ratio must be greater than 0 and at most 1, got {self.ratio}")
        if self.truncate_to is not None and self.truncate_to < 1:
            raise ValueError(f"truncation length must be at least 1, got {self.truncate_to}")

    @classmethod
    def parse_drop(cls, spec: str) -> FieldDegradation:
        """Parse ``NAME:RATIO``, e.g. ``CallTrace:0.3``."""
        name, sep, ratio = spec.rpartition(":")
        if not sep:
            raise ValueError(f"expected NAME:RATIO, got {spec!r}")
        return cls(name, _float(ratio))

    @classmethod
    def parse_truncate(cls, spec: str) -> FieldDegradation:
        """Parse ``NAME:LENGTH:RATIO``, e.g. ``CallTrace:60:0.5``."""
        parts = spec.split(":")
        if len(parts) != 3:
            raise ValueError(f"expected NAME:LENGTH:RATIO, got {spec!r}")
        name, length, ratio = parts
        return cls(name, _float(ratio), truncate_to=_int(length))


def _float(value: str) -> float:
    try:
        return float(value)
    except ValueError:
        raise ValueError(f"not a valid number: {value!r}") from None


def _int(value: str) -> int:
    try:
        return int(value)
    except ValueError:
        raise ValueError(f"not a valid integer: {value!r}") from None


def apply(events: Sequence[Event], specs: Sequence[FieldDegradation], ctx: GenContext) -> list[Event]:
    """Return ``events`` with the requested fields dropped or truncated.

    Randomness is drawn only when ``specs`` is non-empty, so leaving it empty keeps the
    output byte-identical to a run without degradation.
    """
    if not specs:
        return list(events)
    out: list[Event] = []
    for event in events:
        fields: dict[str, Any] = event.fields
        hit: list[str] = []
        for spec in specs:
            value = fields.get(spec.field)
            if value is None:
                continue
            if spec.truncate_to is not None and not (
                isinstance(value, str) and len(value) > spec.truncate_to
            ):
                continue
            if ctx.rng.random() >= spec.ratio:
                continue
            if fields is event.fields:
                fields = dict(fields)  # copy on first change; never mutate the original
            if spec.truncate_to is None:
                del fields[spec.field]
            else:
                fields[spec.field] = value[: spec.truncate_to]
            if spec.field not in hit:
                hit.append(spec.field)
        out.append(replace(event, fields=fields, degraded=(*event.degraded, *hit)) if hit else event)
    return out

"""Output formats."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Literal, TextIO

from trazas.events import Event

Format = Literal["jsonl", "raw"]
FORMATS: tuple[Format, ...] = ("jsonl", "raw")


class UnsupportedFormatError(ValueError):
    pass


def write(events: Iterable[Event], out: TextIO, fmt: Format, *, labels: bool = False) -> int:
    """Write events to ``out``; returns the number written."""
    n = 0
    for event in events:
        if fmt == "jsonl":
            line = json.dumps(event.to_record(include_labels=labels), ensure_ascii=False)
        elif event.raw is not None:
            line = event.raw
        else:
            raise UnsupportedFormatError(f"source {event.source!r} has no raw text form; use --format jsonl")
        out.write(line + "\n")
        n += 1
    return n

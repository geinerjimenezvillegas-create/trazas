"""Core event model."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

Source = Literal["windows_security", "windows_system", "sysmon", "linux_auth"]


def iso_utc(ts: datetime) -> str:
    """Render a timezone-aware datetime as ISO 8601 UTC with millisecond precision."""
    if ts.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return ts.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class Event:
    """A single synthetic log event.

    ``fields`` follows the column names of the closest well-known schema
    (Microsoft Sentinel ``SecurityEvent`` for Windows, syslog/auth.log for Linux)
    so the output can be loaded directly into tools that expect those names.
    """

    timestamp: datetime
    source: Source
    fields: dict[str, Any]
    scenario: str
    malicious: bool = False
    technique: str | None = None
    raw: str | None = field(default=None, compare=False)

    def to_record(self, *, include_labels: bool = False) -> dict[str, Any]:
        record: dict[str, Any] = {"TimeGenerated": iso_utc(self.timestamp), "Source": self.source}
        record.update(self.fields)
        if include_labels:
            record["_trazas"] = {
                "scenario": self.scenario,
                "malicious": self.malicious,
                "technique": self.technique,
            }
        return record

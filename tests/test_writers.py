import io
from datetime import datetime

import pytest

from trazas import engine
from trazas.writers import UnsupportedFormatError, write


def test_raw_unsupported_for_windows(start: datetime) -> None:
    events = engine.generate(["windows-bruteforce"], seed=1, start=start, noise=0)
    with pytest.raises(UnsupportedFormatError, match="no raw text form"):
        write(events, io.StringIO(), "raw")


def test_jsonl_one_line_per_event(start: datetime) -> None:
    events = engine.generate(["ssh-bruteforce"], seed=1, start=start, noise=5)
    buf = io.StringIO()
    assert write(events, buf, "jsonl") == len(events)
    assert buf.getvalue().count("\n") == len(events)

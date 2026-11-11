from datetime import datetime, timezone

import pytest

START = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def start() -> datetime:
    return START

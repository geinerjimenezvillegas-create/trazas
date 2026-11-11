import json
from collections.abc import Callable
from datetime import datetime

import pytest

from trazas import engine
from trazas.cli import main
from trazas.degrade import FieldDegradation
from trazas.events import Event


def _gen(start: datetime, *specs: FieldDegradation) -> list[Event]:
    return engine.generate(["lsass-dump"], seed=1, start=start, noise=2000, degrade=specs)


START = "2026-01-01T00:00:00Z"


def _records(events: list[Event]) -> list[dict[str, object]]:
    return [e.to_record(include_labels=True) for e in events]


def _with_calltrace(events: list[Event]) -> list[Event]:
    return [e for e in events if e.fields.get("EventID") == 10]


def test_no_degradation_is_byte_identical(start: datetime) -> None:
    """Existing datasets (and the numbers quoted in the docs) must not change."""
    assert _records(engine.generate(["lsass-dump"], seed=1, start=start, noise=2000)) == _records(_gen(start))


def test_degradation_only_touches_the_requested_field(start: datetime) -> None:
    clean = _gen(start)
    degraded = _gen(start, FieldDegradation("CallTrace", 0.5))
    assert len(clean) == len(degraded)
    for a, b in zip(clean, degraded, strict=True):
        assert a.timestamp == b.timestamp
        assert a.malicious == b.malicious
        assert {k: v for k, v in a.fields.items() if k != "CallTrace"} == {
            k: v for k, v in b.fields.items() if k != "CallTrace"
        }


def test_drop_all_removes_field_and_labels_it(start: datetime) -> None:
    events = _gen(start, FieldDegradation("CallTrace", 1.0))
    access = _with_calltrace(events)
    assert access
    assert all("CallTrace" not in e.fields for e in access)
    assert all(e.degraded == ("CallTrace",) for e in access)
    assert all(e.to_record(include_labels=True)["_trazas"]["degraded"] == ["CallTrace"] for e in access)
    # Events without the field are left alone and carry no degradation label.
    others = [e for e in events if e.fields.get("EventID") != 10]
    assert not any(e.degraded for e in others)
    assert all("degraded" not in e.to_record(include_labels=True)["_trazas"] for e in others)


def test_drop_ratio_is_roughly_respected(start: datetime) -> None:
    events = _gen(start, FieldDegradation("CallTrace", 0.3))
    access = _with_calltrace(events)
    share = sum(1 for e in access if e.degraded) / len(access)
    assert 0.15 < share < 0.45


def test_degradation_is_deterministic(start: datetime) -> None:
    specs = [FieldDegradation("CallTrace", 0.4), FieldDegradation("SourceImage", 0.2, truncate_to=10)]
    a = _gen(start, *specs)
    b = _gen(start, *specs)
    assert _records(a) == _records(b)


def test_truncate_cuts_long_strings_only(start: datetime) -> None:
    clean = _gen(start)
    cut = _gen(start, FieldDegradation("CallTrace", 1.0, truncate_to=60))
    for a, b in zip(_with_calltrace(clean), _with_calltrace(cut), strict=True):
        assert b.fields["CallTrace"] == a.fields["CallTrace"][:60]
        assert b.degraded == (("CallTrace",) if len(a.fields["CallTrace"]) > 60 else ())


def test_truncate_ignores_non_strings(start: datetime) -> None:
    events = _gen(start, FieldDegradation("EventID", 1.0, truncate_to=1))
    assert not any(e.degraded for e in events)


def test_drop_then_truncate_same_field(start: datetime) -> None:
    specs = [FieldDegradation("CallTrace", 1.0), FieldDegradation("CallTrace", 1.0, truncate_to=5)]
    events = _gen(start, *specs)
    assert all(e.degraded == ("CallTrace",) for e in _with_calltrace(events))


def test_two_truncations_label_field_once(start: datetime) -> None:
    specs = [
        FieldDegradation("CallTrace", 1.0, truncate_to=80),
        FieldDegradation("CallTrace", 1.0, truncate_to=40),
    ]
    access = _with_calltrace(_gen(start, *specs))
    assert all(len(e.fields["CallTrace"]) == 40 for e in access)
    assert all(e.degraded == ("CallTrace",) for e in access)


@pytest.mark.parametrize(
    ("factory", "spec", "message"),
    [
        (FieldDegradation.parse_drop, "CallTrace", "NAME:RATIO"),
        (FieldDegradation.parse_drop, "CallTrace:abc", "valid number"),
        (FieldDegradation.parse_drop, "CallTrace:0", "ratio"),
        (FieldDegradation.parse_drop, "CallTrace:1.5", "ratio"),
        (FieldDegradation.parse_drop, "CallTrace:nan", "ratio"),
        (FieldDegradation.parse_drop, "Call Trace:0.5", "field name"),
        (FieldDegradation.parse_drop, ":0.5", "field name"),
        (FieldDegradation.parse_truncate, "CallTrace:0.5", "NAME:LENGTH:RATIO"),
        (FieldDegradation.parse_truncate, "CallTrace:x:0.5", "valid integer"),
        (FieldDegradation.parse_truncate, "CallTrace:0:0.5", "length"),
    ],
)
def test_invalid_specs(factory: Callable[[str], FieldDegradation], spec: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        factory(spec)


def test_valid_specs_parse() -> None:
    assert FieldDegradation.parse_drop("CallTrace:0.3") == FieldDegradation("CallTrace", 0.3)
    assert FieldDegradation.parse_truncate("CallTrace:60:1") == FieldDegradation("CallTrace", 1.0, 60)


# --- CLI ------------------------------------------------------------------------


def test_cli_drop_field(capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["generate", "lsass-dump", "-s", "1", "--start", START, "-n", "300", "--labels"]
    assert main([*argv, "--drop-field", "CallTrace:1"]) == 0
    captured = capsys.readouterr()
    records = [json.loads(line) for line in captured.out.splitlines()]
    access = [r for r in records if r["EventID"] == 10]
    assert access
    assert all("CallTrace" not in r and r["_trazas"]["degraded"] == ["CallTrace"] for r in access)
    assert f"degraded={len(access)}" in captured.err


def test_cli_truncate_field(capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["generate", "lsass-dump", "-s", "1", "--start", START, "-n", "300"]
    assert main([*argv, "--truncate-field", "CallTrace:40:1"]) == 0
    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert all(len(r["CallTrace"]) <= 40 for r in records if r["EventID"] == 10)


def test_cli_without_degradation_has_no_summary(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["generate", "lsass-dump", "-s", "1", "--start", START, "-n", "0"]) == 0
    assert "degraded=" not in capsys.readouterr().err


def test_cli_degradation_rejects_raw(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["generate", "ssh-bruteforce", "-s", "1", "-f", "raw", "--drop-field", "SrcIp:0.5"]) == 2
    assert "need --format jsonl" in capsys.readouterr().err


@pytest.mark.parametrize(
    "extra",
    [["--drop-field", "CallTrace:2"], ["--drop-field", "CallTrace"], ["--truncate-field", "CallTrace:0.5"]],
)
def test_cli_bad_specs_exit_2(extra: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["generate", "lsass-dump", *extra])
    assert exc.value.code == 2

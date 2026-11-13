import json
from datetime import datetime
from pathlib import Path

import pytest

from trazas import engine
from trazas.cli import main
from trazas.degrade import FieldDegradation
from trazas.scenarios import REGISTRY
from trazas.schema import EVENT_COLUMNS, LABEL_COLUMNS, kql_create_table

START = "2026-01-01T00:00:00Z"
# Python value types each KQL column type accepts in the JSON output.
COMPATIBLE: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "datetime": (str,),  # ISO 8601 text, parsed on ingestion
    "int": (int,),
    "long": (int,),
    "bool": (bool,),
    "dynamic": (dict, list),
}


def _all_records(start: datetime) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for seed in range(15):
        for event in engine.generate(sorted(REGISTRY), seed=seed, start=start, noise=300):
            records.append(event.to_record(include_labels=True))
    return records


def test_schema_covers_every_generated_field(start: datetime) -> None:
    """Adding a field to a scenario without adding it to the schema must fail CI."""
    columns = dict(EVENT_COLUMNS)
    for record in _all_records(start):
        for name, value in record.items():
            assert name in columns, f"field {name!r} missing from trazas.schema.EVENT_COLUMNS"
            if value is not None:
                kql_type = columns[name]
                assert isinstance(value, COMPATIBLE[kql_type]), (name, kql_type, value)
                assert not (isinstance(value, bool) and kql_type in {"int", "long"}), name


def test_schema_has_no_stale_columns(start: datetime) -> None:
    seen = {name for record in _all_records(start) for name in record}
    stale = {name for name, _ in EVENT_COLUMNS} - seen
    assert not stale, f"columns no generator emits any more: {sorted(stale)}"


def test_schema_has_no_duplicates() -> None:
    names = [name for name, _ in EVENT_COLUMNS]
    assert len(names) == len(set(names))


def test_label_schema_matches_label_records(start: datetime) -> None:
    columns = dict(LABEL_COLUMNS)
    events = engine.generate(
        ["lsass-dump"], seed=1, start=start, noise=300, degrade=[FieldDegradation("CallTrace", 0.5)]
    )
    keys_seen: set[str] = set()
    for event in events:
        for name, value in event.label_record().items():
            assert name in columns, name
            keys_seen.add(name)
            if value is not None:
                assert isinstance(value, COMPATIBLE[columns[name]]), (name, value)
    assert keys_seen == set(columns)


def test_kql_create_table() -> None:
    cmd = kql_create_table("T", [("a", "string"), ("b", "int")])
    assert cmd == ".create-merge table T (a: string, b: int)"
    with pytest.raises(ValueError, match="invalid table name"):
        kql_create_table("bad name; .drop table X", [("a", "string")])


# --- event ids and labels file --------------------------------------------------


def test_event_ids_are_sequential_and_deterministic(start: datetime) -> None:
    a = engine.generate(sorted(REGISTRY), seed=3, start=start, noise=100)
    b = engine.generate(sorted(REGISTRY), seed=3, start=start, noise=100)
    assert [e.event_id for e in a] == list(range(1, len(a) + 1))
    assert [e.to_record() for e in a] == [e.to_record() for e in b]


def test_labels_file_joins_with_dataset(tmp_path: Path) -> None:
    data, truth = tmp_path / "data.jsonl", tmp_path / "truth.jsonl"
    argv = ["generate", "lsass-dump", "-s", "1", "--start", START, "-n", "500"]
    assert main([*argv, "-o", str(data), "--labels-file", str(truth)]) == 0
    records = [json.loads(line) for line in data.read_text(encoding="utf-8").splitlines()]
    labels = [json.loads(line) for line in truth.read_text(encoding="utf-8").splitlines()]
    assert all("_trazas" not in r for r in records), "the dataset itself stays blind"
    by_id = {lab["TrazasEventId"]: lab for lab in labels}
    assert sorted(by_id) == sorted(r["TrazasEventId"] for r in records)
    attack = [r for r in records if by_id[r["TrazasEventId"]]["malicious"]]
    assert [r["EventID"] for r in attack] == [1, 10, 11]


def test_labels_file_matches_inline_labels(tmp_path: Path) -> None:
    data, truth = tmp_path / "data.jsonl", tmp_path / "truth.jsonl"
    argv = ["generate", "windows-spray", "-s", "2", "--start", START, "-n", "50", "--labels"]
    assert main([*argv, "-o", str(data), "--labels-file", str(truth)]) == 0
    inline = [json.loads(line)["_trazas"] for line in data.read_text(encoding="utf-8").splitlines()]
    separate = [json.loads(line) for line in truth.read_text(encoding="utf-8").splitlines()]
    assert [{k: v for k, v in s.items() if k != "TrazasEventId"} for s in separate] == inline


def test_labels_file_refuses_to_overwrite_and_writes_nothing(tmp_path: Path) -> None:
    data, truth = tmp_path / "data.jsonl", tmp_path / "truth.jsonl"
    truth.write_text("keep me", encoding="utf-8")
    argv = ["generate", "ssh-bruteforce", "-s", "1", "-o", str(data), "--labels-file", str(truth)]
    assert main(argv) == 1
    assert not data.exists(), "no half-written dataset when a target is refused"
    assert truth.read_text(encoding="utf-8") == "keep me"
    assert main([*argv, "--force"]) == 0
    assert truth.read_text(encoding="utf-8").startswith('{"TrazasEventId": 1')


def test_labels_file_to_stdout_dataset(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    truth = tmp_path / "truth.jsonl"
    assert main(["generate", "ssh-bruteforce", "-s", "1", "-n", "3", "--labels-file", str(truth)]) == 0
    out_ids = [json.loads(line)["TrazasEventId"] for line in capsys.readouterr().out.splitlines()]
    truth_ids = [json.loads(line)["TrazasEventId"] for line in truth.read_text(encoding="utf-8").splitlines()]
    assert out_ids == truth_ids


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["-f", "raw"], "needs --format jsonl"),
        (["-o", "same.jsonl"], "must differ from --output"),
    ],
)
def test_labels_file_rejected_combinations(
    extra: list[str],
    message: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["generate", "ssh-bruteforce", "-s", "1", "--labels-file", "same.jsonl", *extra]) == 2
    assert message in capsys.readouterr().err


# --- `trazas schema` -------------------------------------------------------------


def test_cli_schema(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["schema"]) == 0
    captured = capsys.readouterr()
    events_cmd, labels_cmd = captured.out.strip().split("\n\n")
    assert events_cmd.startswith(".create-merge table SecurityEvent (TimeGenerated: datetime,")
    assert "CallTrace: string" in events_cmd
    assert events_cmd.endswith("_trazas: dynamic)")
    assert labels_cmd.startswith(".create-merge table TrazasLabels (TrazasEventId: long,")
    assert "Shift+Enter" in captured.err


def test_cli_schema_custom_names(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["schema", "--table", "Lab", "--labels-table", "Truth"]) == 0
    out = capsys.readouterr().out
    assert ".create-merge table Lab (" in out
    assert ".create-merge table Truth (" in out


def test_cli_schema_invalid_name(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["schema", "--table", "x y"]) == 2
    assert "invalid table name" in capsys.readouterr().err

import json
from pathlib import Path

import pytest

from trazas.cli import main

START = "2026-01-01T00:00:00Z"


def test_list(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list"]) == 0
    out = capsys.readouterr().out
    assert "windows-bruteforce" in out
    assert "T1110.001" in out


def test_describe(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["describe", "psexec-lateral"]) == 0
    assert "attack.mitre.org/techniques/T1021/002/" in capsys.readouterr().out


def test_generate_jsonl_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["generate", "windows-bruteforce", "-s", "1", "--start", START, "-n", "10", "--labels"]) == 0
    captured = capsys.readouterr()
    records = [json.loads(line) for line in captured.out.splitlines()]
    assert records
    assert all("_trazas" in r for r in records)
    assert "seed=1" in captured.err


def test_labels_are_opt_in(capsys: pytest.CaptureFixture[str]) -> None:
    main(["generate", "ssh-bruteforce", "-s", "1", "--start", START])
    assert "_trazas" not in capsys.readouterr().out


def test_generate_raw_linux(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["generate", "ssh-bruteforce", "-s", "1", "--start", START, "-f", "raw"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert any("Failed password" in line for line in lines)
    assert all(" sshd[" in line for line in lines)


def test_raw_rejected_for_windows(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["generate", "windows-spray", "-s", "1", "-f", "raw"]) == 2
    assert "only supports Linux" in capsys.readouterr().err


def test_output_file_not_overwritten_without_force(tmp_path: Path) -> None:
    out = tmp_path / "out.jsonl"
    out.write_text("keep me", encoding="utf-8")
    assert main(["generate", "ssh-bruteforce", "-s", "1", "-o", str(out)]) == 1
    assert out.read_text(encoding="utf-8") == "keep me"
    assert main(["generate", "ssh-bruteforce", "-s", "1", "-o", str(out), "--force"]) == 0
    assert out.read_text(encoding="utf-8").startswith("{")


def test_output_file_reproducible(tmp_path: Path) -> None:
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    args = ["generate", "windows-spray", "psexec-lateral", "-s", "9", "--start", START]
    assert main([*args, "-o", str(a)]) == 0
    assert main([*args, "-o", str(b)]) == 0
    assert a.read_bytes() == b.read_bytes()


def test_random_seed_is_reported(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["generate", "ssh-bruteforce", "-n", "0"]) == 0
    assert "seed=" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        ["generate", "does-not-exist"],
        ["generate", "ssh-bruteforce", "--start", "yesterday"],
        ["generate", "ssh-bruteforce", "-n", "-5"],
    ],
)
def test_bad_arguments_exit_2(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2


def test_naive_start_assumed_utc(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["generate", "ssh-bruteforce", "-s", "1", "--start", "2026-01-01T00:00:00", "-n", "0"]) == 0
    first = json.loads(capsys.readouterr().out.splitlines()[0])
    assert first["TimeGenerated"].startswith("2026-01-01T")

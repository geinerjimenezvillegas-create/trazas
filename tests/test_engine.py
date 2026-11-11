import ipaddress
from datetime import datetime, timezone

import pytest

from trazas import engine
from trazas.events import iso_utc
from trazas.scenarios import REGISTRY

ALL_IDS = sorted(REGISTRY)
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _ip_of(record_fields: dict[str, object]) -> str | None:
    value = record_fields.get("IpAddress") or record_fields.get("SrcIp")
    return value if isinstance(value, str) and value not in {"-", ""} else None


def test_same_seed_is_deterministic(start: datetime) -> None:
    a = engine.generate(ALL_IDS, seed=7, start=start)
    b = engine.generate(ALL_IDS, seed=7, start=start)
    assert [e.to_record(include_labels=True) for e in a] == [e.to_record(include_labels=True) for e in b]


def test_different_seed_differs(start: datetime) -> None:
    a = engine.generate(["windows-bruteforce"], seed=1, start=start)
    b = engine.generate(["windows-bruteforce"], seed=2, start=start)
    assert [e.fields for e in a] != [e.fields for e in b]


def test_events_are_sorted_and_after_start(start: datetime) -> None:
    events = engine.generate(ALL_IDS, seed=3, start=start)
    stamps = [e.timestamp for e in events]
    assert stamps == sorted(stamps)
    assert all(ts >= start for ts in stamps)


@pytest.mark.parametrize("scenario_id", ALL_IDS)
def test_each_scenario_emits_labelled_malicious_events(scenario_id: str, start: datetime) -> None:
    events = engine.generate([scenario_id], seed=11, start=start, noise=50)
    malicious = [e for e in events if e.malicious]
    assert malicious, "scenario produced no malicious events"
    techniques = set(REGISTRY[scenario_id].techniques)
    assert {e.technique for e in malicious} <= techniques
    assert all(e.scenario == scenario_id for e in malicious)
    assert sum(not e.malicious for e in events) == 50


@pytest.mark.parametrize("seed", range(20))
def test_external_ips_are_documentation_ranges(seed: int, start: datetime) -> None:
    """Generated data must never reference real public infrastructure."""
    for event in engine.generate(ALL_IDS, seed=seed, start=start):
        raw_ip = _ip_of(event.fields)
        if raw_ip is None:
            continue
        ip = ipaddress.ip_address(raw_ip)
        assert ip.is_private or ip.is_loopback or any(ip in net for net in DOC_NETS), raw_ip


def test_bruteforce_ends_in_success_from_attacker(start: datetime) -> None:
    events = engine.generate(["windows-bruteforce"], seed=5, start=start, noise=0)
    assert {e.fields["EventID"] for e in events[:-1]} == {4625}
    assert events[-1].fields["EventID"] == 4624
    assert len({e.fields["IpAddress"] for e in events}) == 1


def test_spray_targets_many_accounts(start: datetime) -> None:
    events = engine.generate(["windows-spray"], seed=5, start=start, noise=0)
    users = {e.fields["TargetUserName"] for e in events}
    assert len(users) >= 15
    assert {e.fields["SubStatus"] for e in events if e.fields["EventID"] == 4625} == {
        "0xc000006a",
        "0xc0000064",
    }


def test_psexec_chain(start: datetime) -> None:
    events = engine.generate(["psexec-lateral"], seed=5, start=start, noise=0)
    ids = [e.fields["EventID"] for e in events]
    assert ids[:5] == [4624, 5140, 5140, 7045, 1]
    assert any(e.fields.get("ServiceName") == "PSEXESVC" for e in events)


def test_duplicate_scenarios_are_deduplicated(start: datetime) -> None:
    once = engine.generate(["ssh-bruteforce"], seed=1, start=start)
    twice = engine.generate(["ssh-bruteforce", "ssh-bruteforce"], seed=1, start=start)
    assert len(once) == len(twice)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"scenario_ids": []}, "at least one"),
        ({"noise": -1}, "noise"),
        ({"window_s": 0}, "window"),
        ({"scenario_ids": ["nope"]}, "unknown scenario"),
    ],
)
def test_invalid_arguments(kwargs: dict[str, object], message: str, start: datetime) -> None:
    params: dict[str, object] = {"scenario_ids": ["ssh-bruteforce"], "seed": 1, "start": start}
    params.update(kwargs)
    with pytest.raises((ValueError, KeyError), match=message):
        engine.generate(**params)  # type: ignore[arg-type]


def test_naive_start_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        engine.generate(["ssh-bruteforce"], seed=1, start=datetime(2026, 1, 1))  # noqa: DTZ001


def test_timestamps_render_utc() -> None:
    assert iso_utc(datetime(2026, 1, 1, tzinfo=timezone.utc)) == "2026-01-01T00:00:00.000Z"
    with pytest.raises(ValueError, match="timezone-aware"):
        iso_utc(datetime(2026, 1, 1))  # noqa: DTZ001

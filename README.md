# trazas

[![CI](https://github.com/geinerjimenezvillegas-create/trazas/actions/workflows/ci.yml/badge.svg)](https://github.com/geinerjimenezvillegas-create/trazas/actions/workflows/ci.yml)
[![CodeQL](https://github.com/geinerjimenezvillegas-create/trazas/actions/workflows/codeql.yml/badge.svg)](https://github.com/geinerjimenezvillegas-create/trazas/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/geinerjimenezvillegas-create/trazas/badge)](https://scorecard.dev/viewer/?uri=github.com/geinerjimenezvillegas-create/trazas)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Realistic, labelled attack logs for testing detection rules — no lab required.**

🇪🇸 [Leer en español](README.es.md)

Writing a detection is easy; proving it works is hard. Most people don't have a
lab with domain controllers, attackers and months of baseline traffic. `trazas`
generates that data for you: attack chains mapped to MITRE ATT&CK, mixed with
benign noise (including look-alikes that *should not* fire your rule), with
optional ground-truth labels so you can measure true and false positives.

```console
$ pip install trazas
$ trazas generate windows-bruteforce psexec-lateral --seed 42 --labels -o dataset.jsonl
trazas: 248 events, seed=42, start=2026-11-10T23:00:00+00:00
```

## Why look-alikes matter

A typical first rule for LSASS credential dumping flags suspicious access masks:

```kql
SecurityEvent
| where EventID == 10 and TargetImage endswith "lsass.exe"
| where GrantedAccess in ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff")
```

Run it on `trazas generate lsass-dump --seed 1 --start 2026-01-01T00:00:00Z --noise 2000 --labels`
and it catches the attack, **plus 89 false positives**: Defender asks for `0x1010`
(the same mask as Mimikatz) and the EDR sensor asks for `0x1fffff`. Looking at the
`CallTrace` instead:

```kql
SecurityEvent
| where EventID == 10 and TargetImage endswith "lsass.exe"
| where GrantedAccess in ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff")
// Look at HOW lsass was opened, not only the access mask:
| where CallTrace has_any ("dbgcore.dll", "dbghelp.dll", "comsvcs.dll")  // minidump APIs
     or CallTrace contains "UNKNOWN("                                     // code running from memory
```

→ **1 true positive, 0 false positives**, across all three dumping variants (seeds 1, 5
and 7 give comsvcs, Mimikatz and procdump). Walkthrough in
[docs/testing-detections.md](docs/testing-detections.md#example-lsass-dumping-and-look-alikes).

## Features

- **Detection-ready schemas** — Windows events use Microsoft Sentinel `SecurityEvent`
  column names (`EventID`, `TargetUserName`, `LogonType`, `IpAddress`…); Linux events
  are real `auth.log` lines.
- **Reproducible** — same `--seed` + `--start` ⇒ byte-identical output. Perfect for
  regression tests of your rules in CI.
- **Ground truth** — `--labels` adds `_trazas.malicious` and `_trazas.technique` to every
  record.
- **Realistic noise** — normal logons, admin share use, honest password typos, and
  security software touching `lsass.exe`.
- **Telemetry gaps** — `--drop-field` / `--truncate-field` remove or cut fields in a share of
  the events, so you can see what your rule does when the data is incomplete.
- **Safe by design** — external IPs come only from RFC 5737 documentation ranges,
  internal ones from RFC 1918, domains from `example.com`. Zero runtime dependencies.

## Scenarios

| ID | Platform | ATT&CK | What happens |
|---|---|---|---|
| `windows-bruteforce` | Windows | T1110.001 | Burst of 4625 against one account from one external IP, then 4624 |
| `windows-spray` | Windows | T1110.003 | One password against many accounts (real and invalid), slow, one success |
| `psexec-lateral` | Windows | T1021.002, T1569.002 | 4624 type 3 → 5140 `ADMIN$` → 7045 `PSEXESVC` → Sysmon 1 recon as SYSTEM |
| `lsass-dump` | Windows | T1003.001 | Sysmon 1 dumper (comsvcs `MiniDump`, `procdump -ma` or renamed Mimikatz) → Sysmon 10 on `lsass.exe` → Sysmon 11 `.dmp`; noise adds benign Defender/EDR lsass access |
| `ssh-bruteforce` | Linux | T1110.001 | sshd failures with common usernames, then `Accepted password` |

Run `trazas list` and `trazas describe <id>` for details.

## Usage

```text
trazas generate SCENARIO [SCENARIO ...]
  -s, --seed INT       PRNG seed (random if omitted; printed so you can reproduce)
  --start ISO8601      start time (default: now, UTC)
  -n, --noise INT      benign events per platform (default: 200)
  -f, --format         jsonl (default) | raw  (raw = native text, Linux only)
  -o, --output PATH    write to file (refuses to overwrite without --force)
  --labels             add ground-truth labels
  --drop-field NAME:RATIO          remove a field from that share of events (e.g. CallTrace:0.3)
  --truncate-field NAME:LEN:RATIO  cut a string field to LEN characters in that share of events
```

## Testing a KQL rule without Sentinel

1. Create a free [Azure Data Explorer cluster](https://dataexplorer.azure.com/freecluster).
2. Generate data: `trazas generate windows-bruteforce windows-spray -s 1 --labels -o events.jsonl`
3. Ingest `events.jsonl` into a table named `SecurityEvent` (JSON format).
4. Run your rule. Example:

```kql
SecurityEvent
| where EventID == 4625
| summarize Failures = count(), Accounts = dcount(TargetUserName) by IpAddress, bin(TimeGenerated, 10m)
| where Failures > 20 or Accounts > 10
```

Then compare against `_trazas.malicious` to count true and false positives. See
[docs/testing-detections.md](docs/testing-detections.md).

## Contributing

New scenarios are very welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Please report
security issues privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Generated data is synthetic; any resemblance to real users is coincidental.

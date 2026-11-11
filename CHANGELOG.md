# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Scenario `lsass-dump` (T1003.001): Sysmon 1 → Sysmon 10 ProcessAccess on `lsass.exe`
  → Sysmon 11 dump file, in three variants (comsvcs.dll `MiniDump`, `procdump -ma`,
  renamed Mimikatz with an `UNKNOWN` CallTrace frame).
- Windows noise now includes benign Sysmon 10 lsass access from Defender (`0x1010`),
  the EDR sensor (`0x1fffff`) and svchost (`0x1000`) as look-alikes.

### Changed

- Windows noise for a given seed differs from 0.1.0 because of the new look-alike events.

## [0.1.0] - 2026-11-10

### Added

- `trazas list`, `describe` and `generate` commands.
- Scenarios: `windows-bruteforce` (T1110.001), `windows-spray` (T1110.003),
  `psexec-lateral` (T1021.002, T1569.002), `ssh-bruteforce` (T1110.001).
- Benign background noise for Windows and Linux.
- `jsonl` output with Sentinel `SecurityEvent` column names and `raw` auth.log output.
- Optional ground-truth labels (`--labels`).

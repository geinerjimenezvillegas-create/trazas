# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-11

### Added

- `--drop-field NAME:RATIO` and `--truncate-field NAME:LEN:RATIO` to simulate incomplete
  telemetry, reproducible from the seed. Only the named field changes; the rest of the
  dataset is identical to an undegraded run. With `--labels`, affected events list the
  degraded fields in `_trazas.degraded`. Without these options the output is unchanged.
- Docs: "Example: incomplete telemetry" walkthrough (missing and truncated `CallTrace`,
  a fail-closed rule, and a telemetry health query).
- README: "Why look-alikes matter" demo (an access-mask-only LSASS rule gives 1 TP / 89 FP;
  adding a CallTrace condition gives 1 TP / 0 FP), with a full walkthrough in the docs.

## [0.1.0] - 2026-11-11

### Added

- `trazas list`, `describe` and `generate` commands.
- Scenarios: `windows-bruteforce` (T1110.001), `windows-spray` (T1110.003),
  `psexec-lateral` (T1021.002, T1569.002), `ssh-bruteforce` (T1110.001).
- Scenario `lsass-dump` (T1003.001): Sysmon 1 → Sysmon 10 ProcessAccess on `lsass.exe`
  → Sysmon 11 dump file, in three variants (comsvcs.dll `MiniDump`, `procdump -ma`,
  renamed Mimikatz with an `UNKNOWN` CallTrace frame).
- Benign background noise for Windows and Linux, including look-alike Sysmon 10 lsass
  access from Defender (`0x1010`), the EDR sensor (`0x1fffff`) and svchost (`0x1000`).
- `jsonl` output with Sentinel `SecurityEvent` column names and `raw` auth.log output.
- Optional ground-truth labels (`--labels`).

[Unreleased]: https://github.com/geinerjimenezvillegas-create/trazas/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/geinerjimenezvillegas-create/trazas/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/geinerjimenezvillegas-create/trazas/releases/tag/v0.1.0

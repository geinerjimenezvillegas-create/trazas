# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-10

### Added

- `trazas list`, `describe` and `generate` commands.
- Scenarios: `windows-bruteforce` (T1110.001), `windows-spray` (T1110.003),
  `psexec-lateral` (T1021.002, T1569.002), `ssh-bruteforce` (T1110.001).
- Benign background noise for Windows and Linux.
- `jsonl` output with Sentinel `SecurityEvent` column names and `raw` auth.log output.
- Optional ground-truth labels (`--labels`).

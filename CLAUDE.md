# CLAUDE.md — trazas

Synthetic, labelled attack-log generator for testing detection rules. Python ≥3.10,
src layout, **zero runtime dependencies** (keep it that way; dev deps only in `[dev]`).

## Commands

```bash
pip install -e ".[dev]"          # setup
ruff check . && ruff format --check . && mypy && pytest --cov   # must all pass
python -m trazas list            # smoke test
```

## Architecture

- `src/trazas/context.py` — `GenContext`: single seeded RNG, IP/user/host helpers.
- `src/trazas/windows.py`, `linux.py` — event builders (Sentinel `SecurityEvent` column names / auth.log).
- `src/trazas/scenarios/` — one `Scenario` subclass per attack; registered explicitly in `__init__.py`.
- `src/trazas/noise.py` — benign background + look-alikes.
- `src/trazas/engine.py` — merges scenarios + noise, stable sort by time.
- `src/trazas/cli.py` — argparse CLI (`list`, `describe`, `generate`).

## Non-negotiable rules

- All randomness via `ctx.rng`; never `random` module directly or wall-clock time. Same seed+start ⇒ identical bytes.
- Only RFC 5737 / RFC 1918 IPs and `example.com` domains (enforced by tests).
- Every attacker event: `malicious=True` + ATT&CK `technique`.
- mypy strict and ruff must stay clean; no `# type: ignore` / `noqa` without a reason comment.
- New scenario ⇒ test + row in README.md and README.es.md + CHANGELOG entry.
- Never commit secrets, tokens or real log data. Never weaken workflow `permissions`.
- Conventional Commits. Work on a branch and open a PR; don't push to `main` directly.

## Repo & workflow gotchas

- Repo: `geinerjimenezvillegas-create/trazas` (public). PyPI: `trazas`.
- `main` ruleset: PR required (0 approvals, squash only), 9 required checks (lint, 6 test
  jobs, build, `Analyze (python)`), no force-push/deletion, **signed commits required**.
- **Every commit in a PR must be signed**, even though merges are squashed; one unsigned
  commit blocks the merge. If a branch has unsigned commits, re-sign them
  (`git rebase --force-rebase --gpg-sign main`) onto a *new* branch and open a new PR.
  Don't force-push and never use `gh pr merge --admin`.
- Actions are pinned to full SHAs with a `# vX.Y.Z` comment. Dependabot opens weekly
  grouped PRs; check that each SHA matches its tag (`gh api repos/<a>/commits/<tag>`).
- Changing `noise.py` (thresholds, new event kinds) changes the output for every seed.
  Note it in the CHANGELOG and **re-verify the numbers quoted in README.md, README.es.md and
  `docs/testing-detections.md`** (LSASS demo: seed 1, noise 2000 ⇒ naive rule 1 TP / 89 FP,
  CallTrace rule 1 TP / 0 FP; seeds 1/5/7 = comsvcs/Mimikatz/procdump).

## Releasing

1. Bump `__version__` in `src/trazas/__init__.py`; move `[Unreleased]` into a dated
   section in `CHANGELOG.md` and update the compare links. Merge through a PR.
2. On updated `main`: `git tag -s vX.Y.Z -m "trazas vX.Y.Z"` then `git push origin vX.Y.Z`.
3. `release.yml` builds, attests and waits at the `pypi` environment; the maintainer
   approves it in Actions. Afterwards it publishes to PyPI and creates the GitHub release.
4. Verify: `pip install trazas==X.Y.Z` in a clean venv and
   `gh attestation verify <wheel> --repo geinerjimenezvillegas-create/trazas`.

## Status (2026-11-11)

- Initial setup from the original TODO is done: placeholders, SHA pins, pre-commit
  update, `docs/github-setup.md` checklist (fully applied), `lsass-dump` scenario.
- **v0.1.0 released** to PyPI and GitHub Releases (5 scenarios). PyPI shows the 0.1.0
  README, without the LSASS demo added later.
- Open `good first issue`s for new scenarios: #10 Kerberoasting (T1558.003), #11 DCSync
  (T1003.006), #12 scheduled task (T1053.005), #13 log clearing (T1070.001). Each issue
  describes the events and look-alikes; review contributions against it.

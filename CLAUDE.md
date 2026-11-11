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

## Pending work (maintainer TODO)

1. ~~Replace `OWNER` placeholder~~ — done.
2. ~~Pin GitHub Actions to SHAs~~ — done (Dependabot keeps them updated).
3. ~~`pre-commit autoupdate`~~ — done.
4. `docs/github-setup.md`: everything scriptable is applied. Still manual: account 2FA,
   commit signing (then add *Require signed commits* to the `main` ruleset), PyPI account
   and pending trusted publisher.
5. Next scenario: LSASS credential dumping (T1003.001) — Sysmon 10 ProcessAccess on lsass.exe, plus benign look-alikes (AV/EDR).

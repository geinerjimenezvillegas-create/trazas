# Contributing to trazas

Thanks for helping! Contributions in English or Spanish are welcome. /
¡Gracias! Se aceptan contribuciones en inglés o español.

## Development setup

```console
git clone https://github.com/OWNER/trazas && cd trazas
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
```

Before opening a PR, everything below must pass (CI runs the same):

```console
ruff check . && ruff format --check . && mypy && pytest --cov
```

## Adding a scenario

1. Open a *New scenario* issue first so we can agree on the event sequence.
2. Create `src/trazas/scenarios/<name>.py` with a `Scenario` subclass. Set `id`,
   `name`, `description`, `platform` and `techniques`, and implement `generate()`.
3. Build events with the helpers in `trazas.windows` / `trazas.linux`; add a helper if
   a new event type is needed, using the field names of the closest real schema.
4. Register it in `src/trazas/scenarios/__init__.py`.
5. Add a test asserting the important parts of the chain (event IDs, order, fields).
6. Add a row to the scenario tables in both READMEs and a line in `CHANGELOG.md`.

### Rules for scenarios

- **All randomness through `ctx.rng`** — never `random` directly, never wall-clock
  time. Output must be deterministic for a given seed and start.
- **No real infrastructure** — use `ctx.external_ip()`, `ctx.internal_ip()` and the
  `example.com` domain. A test enforces this.
- **Mark every attacker event** with `malicious=True` and its ATT&CK `technique`.
- Prefer realism you can cite: link vendor docs or public DFIR reports in the PR.

## Commits and PRs

- Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`,
  `docs:`, `ci:`…).
- Keep PRs focused; one scenario per PR.
- By contributing you agree your work is licensed under the MIT License.

## Code of Conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).

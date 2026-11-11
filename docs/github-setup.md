# Repository settings checklist (maintainer)

Things that live in GitHub settings, not in the code. Do these once after creating
the public repo.

## Account

- [x] 2FA enabled (passkey or authenticator app) on your GitHub account.
- [x] Commit signing set up (SSH or GPG key marked as *signing key*).

## Settings → General

- [x] Features: Issues on; Wiki off (docs live in the repo); Discussions optional.
- [x] Pull requests: allow **squash merging** only; enable *Automatically delete head branches*.

## Settings → Rules → Rulesets (branch `main`)

- [x] Restrict deletions, block force pushes.
- [x] Require a pull request before merging (1 approval once you have co-maintainers;
      0 while solo, but still go through PRs so CI runs).
- [x] Require status checks: `Lint & type-check`, the `Test (...)` jobs,
      `Build & smoke-test package`, `Analyze (python)`.
- [x] Require signed commits.

## Settings → Code security

- [x] Private vulnerability reporting: **on**.
- [x] Dependabot alerts and security updates: **on**.
- [x] Secret scanning and **push protection**: **on**.
- [x] CodeQL: use the workflow in this repo (not "default setup", to avoid running twice).

## Settings → Actions → General

- [x] Workflow permissions: **Read repository contents** (the workflows ask for more
      only where needed).
- [x] Do **not** allow Actions to create or approve pull requests.
- [x] Fork PR workflows: require approval for first-time contributors.

## Settings → Environments

- [x] Create environment `pypi`, restrict to tags `v*`, add yourself as required reviewer.

## PyPI (before the first release)

- [x] Create a PyPI account with 2FA.
- [x] Add a *pending trusted publisher*: project `trazas`, owner `geinerjimenezvillegas-create`, repo `trazas`,
      workflow `release.yml`, environment `pypi`.
- [ ] Release: bump `__version__`, update `CHANGELOG.md`, then
      `git tag -s v0.1.0 && git push --tags`.

## Hardening later

- [x] Pin every action to a full commit SHA (Dependabot keeps them updated).
- [x] Replace the `OWNER` placeholder across the repo with your username.

# Repository settings checklist (maintainer)

Things that live in GitHub settings, not in the code. Do these once after creating
the public repo.

## Account

- [ ] 2FA enabled (passkey or authenticator app) on your GitHub account.
- [ ] Commit signing set up (SSH or GPG key marked as *signing key*).

## Settings → General

- [ ] Features: Issues on; Wiki off (docs live in the repo); Discussions optional.
- [ ] Pull requests: allow **squash merging** only; enable *Automatically delete head branches*.

## Settings → Rules → Rulesets (branch `main`)

- [ ] Restrict deletions, block force pushes.
- [ ] Require a pull request before merging (1 approval once you have co-maintainers;
      0 while solo, but still go through PRs so CI runs).
- [ ] Require status checks: `Lint & type-check`, the `Test (...)` jobs,
      `Build & smoke-test package`, `Analyze (python)`.
- [ ] Require signed commits.

## Settings → Code security

- [ ] Private vulnerability reporting: **on**.
- [ ] Dependabot alerts and security updates: **on**.
- [ ] Secret scanning and **push protection**: **on**.
- [ ] CodeQL: use the workflow in this repo (not "default setup", to avoid running twice).

## Settings → Actions → General

- [ ] Workflow permissions: **Read repository contents** (the workflows ask for more
      only where needed).
- [ ] Do **not** allow Actions to create or approve pull requests.
- [ ] Fork PR workflows: require approval for first-time contributors.

## Settings → Environments

- [ ] Create environment `pypi`, restrict to tags `v*`, add yourself as required reviewer.

## PyPI (before the first release)

- [ ] Create a PyPI account with 2FA.
- [ ] Add a *pending trusted publisher*: project `trazas`, owner `OWNER`, repo `trazas`,
      workflow `release.yml`, environment `pypi`.
- [ ] Release: bump `__version__`, update `CHANGELOG.md`, then
      `git tag -s v0.1.0 && git push --tags`.

## Hardening later

- [ ] Pin every action to a full commit SHA (Dependabot keeps them updated). Tools
      such as `pinact` or StepSecurity's secure-workflow do it automatically.
- [ ] Replace `OWNER` across the repo with your username:
      `grep -rl OWNER . | xargs sed -i 's/OWNER/<your-user>/g'`

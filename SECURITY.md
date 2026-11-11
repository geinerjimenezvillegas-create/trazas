# Security Policy

## Supported versions

Only the latest released version receives fixes while the project is pre-1.0.

## Reporting a vulnerability

**Please do not open public issues for security problems.**

Use GitHub's private reporting: **Security → Report a vulnerability** on this
repository (<https://github.com/geinerjimenezvillegas-create/trazas/security/advisories/new>).

Include the version, the exact command, and the impact you see. You can expect an
acknowledgement within 7 days and a fix or mitigation plan within 30 days for
confirmed issues. Reporters are credited in the advisory unless they prefer otherwise.

## Scope

`trazas` only **writes synthetic log data**. It does not execute attacks, contact
the network, or read system logs. Relevant reports include, for example:

- generated data containing real, routable public IPs, real domains or anything
  resembling real credentials;
- path handling issues when writing output files;
- supply-chain problems in the build or release pipeline.

## Supply-chain measures

- No runtime dependencies.
- Releases are built in GitHub Actions and published to PyPI via Trusted Publishing
  (OIDC, no stored tokens), with signed build provenance. Verify a download with:

  ```console
  gh attestation verify trazas-*.whl --repo geinerjimenezvillegas-create/trazas
  ```

- CodeQL, OpenSSF Scorecard, Dependabot and secret scanning run on the repository.

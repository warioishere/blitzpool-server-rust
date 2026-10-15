# Security policy

## Reporting a vulnerability

Please report security issues privately through
[GitHub's private vulnerability reporting](https://github.com/warioishere/blitzpool-server-rust/security/advisories/new),
not in a public issue.

A useful report says what is affected (file and line, or endpoint), how to
reproduce it, and what an attacker gains. Anything that can move or redirect
block rewards, or lets someone act for an address they do not control, is the
most important class here: payouts go straight from the coinbase to the miners
and cannot be recalled.

## Supported versions

Fixes go into `main` and the next release. Only the latest release, which the
`stable` branch points at, is supported.

# Security policy

## Reporting a vulnerability

Please report security vulnerabilities **privately**, not in a public issue. Use
GitHub's private vulnerability reporting — the **Report a vulnerability** button
under this repository's **Security** tab — or contact the maintainer directly.

Include what you found, how to reproduce it, and the potential impact. You will
get an acknowledgement, and we will work with you on a fix and on disclosure
timing.

## Scope and posture

Agent Guard is a research-stage project (v0.x). The deception layers (the glamour
and the tripwire) are **not** safety-rated; the guarantees live in the pacify
ladder, the signed revocation registry, and the independent controls — never in
an agent staying fooled. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

Agent Guard contains rogue agents only on resources the defender owns (deny,
revoke, isolate, suspend). It never reaches into an agent's own infrastructure —
that "hack-back" is out of scope by design.

## Good to know

- **No secrets in the repo.** Agent Guard's signing and quarantine keys and its
  settings live in your per-user data directory, and are gitignored — they are
  never committed.
- **Signatures** use a hybrid ML-DSA-65 (FIPS 204) + Ed25519 scheme; a signature
  verifies only if both components verify. The revocation registry rejects any
  revocation without a valid circle signature, so it cannot be weaponized into a
  denial-of-service.
- **Supply chain.** CI runs `ruff` and the full test suite on every push and pull
  request; CodeQL scans the code; Dependabot proposes dependency and action
  updates weekly.

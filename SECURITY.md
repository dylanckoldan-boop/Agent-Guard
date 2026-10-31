# Security policy

## Reporting a vulnerability

Please report security vulnerabilities **privately**, not in a public issue. Use
GitHub's private vulnerability reporting — the **Report a vulnerability** button
under this repository's **Security** tab — or contact the maintainer directly.

Include what you found, how to reproduce it, and the potential impact.

Our targets, for a project at this stage:

- **Acknowledgement within 7 days** of your report.
- **Initial assessment within 30 days** — whether it is confirmed, its severity,
  and a rough fix timeline.
- **Coordinated disclosure within 90 days** by default; sooner for a simple fix,
  and we will agree timing with you.

If private vulnerability reporting is unavailable to you, contact the maintainer
at **&lt;security contact — owner to set&gt;**.

### Supported versions

Foldward is pre-1.0; only the latest release receives security fixes.

| Version | Supported |
|--------:|:---------:|
| latest 0.x | ✓ |
| older 0.x | ✗ |

## Scope and posture

Foldward is a research-stage project (v0.x). The deception layers (the glamour
and the tripwire) are **not** safety-rated; the guarantees live in the pacify
ladder, the signed revocation registry, and the independent controls — never in
an agent staying fooled. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

Foldward contains rogue agents only on resources the defender owns (deny,
revoke, isolate, suspend). It never reaches into an agent's own infrastructure —
that "hack-back" is out of scope by design.

## Good to know

- **No secrets in the repo, all state on-device.** Foldward's settings, its
  circle signing key, the agents you register, the revocation registry, the
  hash-chained audit and the quarantine store (with its key) all live in your own
  per-user data directory, readable only by you. Nothing is uploaded, and nothing
  is committed to the repository.
- **Signatures** use a hybrid ML-DSA-65 (FIPS 204) + Ed25519 scheme; a signature
  verifies only if both components verify. The revocation registry rejects any
  revocation without a valid circle signature, so it cannot be weaponized into a
  denial-of-service.
- **Supply chain.** CI runs `ruff` and the full test suite on every push and pull
  request; CodeQL scans the code; Dependabot proposes dependency and action
  updates weekly; workflow actions are pinned to commit SHAs; and CI runs
  `pip-audit` as an advisory dependency scan.

## Website

The website (`site/`) is static HTML and CSS published with GitHub Pages: no
scripts, no cookies, no forms, no sign-in, and nothing loaded from other servers.
Each page sets a strict `Content-Security-Policy` and a `referrer` policy in a
`<meta>` tag. GitHub Pages cannot set HTTP response headers, so header-only
controls (a header-delivered CSP with `frame-ancestors`, `X-Content-Type-Options`,
`Permissions-Policy`, `Cross-Origin-Opener-Policy`, HSTS) can't be sent from there.
With no scripts, forms or sign-in, clickjacking and MIME sniffing have nothing to
act on, so this residual gap is accepted for now; moving to header-capable hosting
(e.g. Cloudflare Pages) would close it and is recorded as a possible future step.

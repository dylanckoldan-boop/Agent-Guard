# Agent Guard

**A containment net for autonomous AI agents — it catches rogue agent activity and pacifies it, reversibly, within your own perimeter.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/) [![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Agent Guard holds an oversight **net** across a fleet of AI agents — natively spawned or *uploaded* onto a host — and watches the water. When an agent goes rogue, Agent Guard **pacifies** it: graduated, reversible-first containment (throttle → quarantine → revoke → suspend → terminate), climbing only as high as the threat demands, and only ever on resources you own. It never reaches into the agent's own infrastructure.

It is a **standalone application**. [sentinel-vision](https://github.com/dylanckoldan-boop/sentinel-vision) and [cryptomigrate](https://github.com/dylanckoldan-boop/Cryptomigrate) are *optional* — detected at runtime, never a dependency. With neither installed, Agent Guard is fully useful; with sentinel-vision installed, the net supercharges it, catching rogue agents **sentinel-vision can't see on its own** and using its firewall and hardened vault to contain them.

## Two threats, one net

An AI agent with tools and network access goes wrong two ways, and Agent Guard catches both:

- **The misaligned agent** — sanctioned, valid credentials, but its objective is wrong at the edges. An *alignment* failure at the machine boundary.
- **The hijacked agent** — a legitimate agent subverted by indirect prompt injection, now acting for someone else. Its first tell is a *network* move — exfiltration, a new C2 endpoint, a reach it never made before.

The principle throughout: **don't trust the model to hold a boundary — constrain what it can reach.** See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design.

## The four layers

Defense in depth — defeating any one layer still leaves the next.

| Layer | Name | Role |
|------:|------|------|
| 1 | **Admission** | Nothing runs unattested; agents carry signed, least-privilege identity. |
| 2 | **The net (tripwire)** | No legitimate agent touches a decoy, so any contact *is* an intrusion — ~zero false positives. |
| 3 | **Pacify ladder** | throttle → quarantine → revoke → suspend → terminate, all inside your own perimeter. |
| 4 | **Consensus + audit** | A flag contains only on a signed quorum; every step is logged in a hash-chained, PQ-signed, tamper-evident chain. |

## Install

```bash
git clone https://github.com/dylanckoldan-boop/Agent-Guard && cd Agent-Guard
pip install -e ".[dev]"      # core + tests
pip install -e ".[gui]"      # add the desktop app (PySide6)
```

Core dependencies are just `psutil` and `cryptography`. Neither partner is pulled in.

## Quick start

```bash
# command line
agent-guard-cli status                 # signer, data location, which partners are present
agent-guard-cli scan                   # detect and score agent processes (exit 1 if any flagged)
agent-guard-cli scan --json            # machine-readable
agent-guard-cli canaries --dir ~/project ~/Downloads   # plant decoy files
agent-guard-cli register --label researcher --actions summarize --hosts api.anthropic.com
agent-guard-cli watch                  # continuous daemon
agent-guard-cli quarantine list
agent-guard-cli attest --json          # PQ-signed attestation of oversight state
agent-guard-cli selftest               # verify the crypto backend

# desktop app
agent-guard                            # the control-room GUI
```

Exit codes: `0` clean · `1` a rogue agent is flagged · `2` error — handy for CI and cron.

## The desktop app

A control-room GUI (PySide6) in the same palette as sentinel-vision:

- **Overview** — status hero, the fleet at a glance, live detections, the pacify ladder.
- **The Net** — every agent process, mapped to its identity and scored on reach and behaviour, with the pacify ladder in a right-click menu.
- **Detections** — the ladder for the latest containment and the signed audit trail.
- **Mesh** — the oversight spiderweb: consensus core, the sentinel voting ring, agents on the rim colored by state, and the "many doors" panel.
- **Quarantine** — neutralized binaries, encrypted and restorable.
- **Settings** — containment authority, oversight mixing, partner status.

## The "many doors" principle

Mix networks shuffle entrances and exits so a watcher can't link them. Agent Guard applies this with **opposite rules for the two planes**:

- **The watched agents' traffic is never mixed** — their east-west flow *is* the net's best detection signal, so it stays fully observable. Data plane watched.
- **The oversight traffic *is* mixed** — sentinel votes and containment commands run padded with cover traffic, so a hijacked agent can't tell which sentinel flagged it or trace the consensus core. Control plane hidden.

Authentication proves *who* is talking; mixing hides *that* they are, and to whom. Time-critical containment commands skip the mix, because the kill switch must be fast.

## Standalone, and Route B

Agent Guard runs entirely on its own. When the partners are installed, it opens a port:

- **sentinel-vision** lends its *hands* — `scan` an agent's binary for a verdict, `block_egress` at the OS firewall, hand the binary to its hardened vault with rollback, and store the audit in its admin-only protected directory (the real Layer-4 Wall). Under Route B, Agent Guard's pages even appear as a tab *inside* sentinel-vision, with no dependency either way.
- **cryptomigrate** is the *notary and crypto lens* — scan a flagged agent's directory for weak crypto, and emit PQ-signed attestations of oversight state.

The integration contract and the exact (additive-only) changes each partner needs are in [`docs/SENTINEL_VISION_INTEGRATION.md`](docs/SENTINEL_VISION_INTEGRATION.md).

## What the tests prove

```bash
pytest -q
```

- **crypto** — the hybrid signer verifies and rejects forgeries; a verify-only handle cannot sign; the audit chain is intact after activity and **breaks under tampering**.
- **registry** — a signed revocation is accepted; a **forged revocation is rejected**, so the registry can't be weaponized into a denial-of-service.
- **tripwire** — contact with a decoy fires the wire; canaries are detected; the glamour shows an agent one thing and a human another.
- **detect** — the pure risk score: a decoy touch is 100, an unregistered agent and fan-out raise it, reasons carry the right sentinel kind.
- **response** — the pacify ladder climbs, revokes, and records; a vanished process degrades gracefully; `release` reverses a suspension.
- **quarantine** — encrypt/restore round-trips and **fails closed if the stored blob is altered**.
- **core / mesh** — a decoy auto-contains; consensus waives quorum on a decoy but holds below threshold; the mix channel pads oversight traffic and bypasses on urgent.
- **integrations** — with no partners installed, everything degrades to Agent Guard's own mechanisms, never an error.

## Standards basis

- **Post-quantum:** FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), NIST IR 8547 (draft transition).
- **AI in operational settings:** the governing rule that humans remain responsible and must be able to bypass, replace, and plan for the failure of the AI.
- Companion projects: [sentinel-vision](https://github.com/dylanckoldan-boop/sentinel-vision) (antimalware; hybrid ML-DSA-65 + Ed25519 signed updates) and [cryptomigrate](https://github.com/dylanckoldan-boop/Cryptomigrate) (crypto discovery, migration, and signed attestation).

## Scope and limitations

A research concept and a working v0.1, not a certified safety system. The deception layers (glamour, tripwire) are not safety-rated; against a sufficiently capable agent the glamour degrades — acceptable only because the guarantees live in the pacify ladder, the signed registry, and the independent controls, never in the agent staying fooled. First-pass agent detection is heuristic and tunable. Process control and firewall actions depend on OS privileges.

## How this was built

The author designed the architecture, the four-layer model, the many-doors principle, and the module structure, and built the implementation with AI assistance (Anthropic's Claude) under that direction. Correctness is established by the test suite and the explicit invariants above, not by assertion — mirroring the companion [cryptomigrate](https://github.com/dylanckoldan-boop/Cryptomigrate) and [machineward](https://github.com/dylanckoldan-boop/machineward) projects.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Dylan C. Koldan.

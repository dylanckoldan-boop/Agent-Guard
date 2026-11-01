# Foldward

**A containment net for autonomous AI agents — it catches rogue agent activity and pacifies it, reversibly, within your own perimeter.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/) [![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Foldward holds an oversight **net** across a fleet of AI agents — natively spawned or *uploaded* onto a host — and watches the water. When an agent goes rogue, Foldward **pacifies** it: graduated, reversible-first containment (throttle → quarantine → revoke → suspend → terminate), climbing only as high as the threat demands, and only ever on resources you own. It never reaches into the agent's own infrastructure.

It is a **standalone application**. [sentinel-vision](https://github.com/dylanckoldan-boop/sentinel-vision) and [cryptomigrate](https://github.com/dylanckoldan-boop/Cryptomigrate) are *optional* — detected at runtime, never a dependency. With neither installed, Foldward is fully useful; with sentinel-vision installed, the net supercharges it, catching rogue agents **sentinel-vision can't see on its own** and using its firewall and hardened vault to contain them.

## Two threats, one net

An AI agent with tools and network access goes wrong two ways, and Foldward catches both:

- **The misaligned agent** — sanctioned, valid credentials, but its objective is wrong at the edges. An *alignment* failure at the machine boundary.
- **The hijacked agent** — a legitimate agent subverted by indirect prompt injection, now acting for someone else. Its first tell is a *network* move — exfiltration, a new C2 endpoint, a reach it never made before.

The principle throughout: **don't trust the model to hold a boundary — constrain what it can reach.** See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design.

## The four layers

The layers work independently, so one failing doesn't switch off the others. All of them run with your rights, so a program running as you can interfere with every layer (see [Scope and limitations](#scope-and-limitations)).

| Layer | Name | Role |
|------:|------|------|
| 1 | **Admission** | Agents you sanction carry a signed, least-privilege identity bound to their process (PID and start time), checked against the revocation registry; an unregistered agent is flagged, not blocked. |
| 2 | **The net (tripwire)** | Canary files that no normal workflow opens. An unregistered agent holding one open is contained; a registered agent is flagged for you; other programs (antivirus, backup) are reported, never contained. Canaries are recognised only from the list of files this install planted. |
| 3 | **Pacify ladder** | throttle → quarantine → revoke → suspend → terminate, all inside your own perimeter. When the ladder reaches suspend, the agent is frozen first. |
| 4 | **Consensus + audit** | A flag contains only after an in-process quorum agrees (a canary held open by an unregistered agent is self-authorizing); every step is logged in a hash-chained, tamper-evident chain whose head can be PQ-signed. |

## Install

```bash
# a released version, pinned to its tag (never whatever main holds that minute)
pip install "foldward[gui] @ git+https://github.com/dylanckoldan-boop/Foldward@v0.2.0"

# or, to work on the code
git clone https://github.com/dylanckoldan-boop/Foldward && cd Foldward
pip install --require-hashes -r requirements/ci.lock && pip install --no-deps -e .
```

Core dependencies are just `psutil` and `cryptography` (47 or newer, for post-quantum signing). Neither partner is pulled in. Each release on GitHub lists the SHA-256 of its files in `SHA256SUMS.txt`. `foldward-cli update` tells you when a newer release exists and prints the pinned command; it never downloads anything itself.

## Quick start

```bash
# command line
foldward-cli status                 # signer, data location, which partners are present
foldward-cli scan                   # detect and score agent processes (exit 1 if any flagged)
foldward-cli scan --json            # machine-readable
foldward-cli canaries --dir ~/project ~/Downloads   # plant decoy files
foldward-cli register --label researcher --actions summarize --hosts api.anthropic.com
foldward-cli watch                  # continuous daemon
foldward-cli quarantine list
foldward-cli attest --json          # PQ-signed attestation of oversight state
foldward-cli selftest               # verify the crypto backend

# desktop app
foldward                            # the control-room GUI
```

Exit codes: `0` clean · `1` a rogue agent is flagged · `2` error — handy for CI and cron.

## The desktop app

A control-room GUI (PySide6) in the same palette as sentinel-vision:

- **Overview** — status hero, the fleet at a glance, live detections, the pacify ladder.
- **The Net** — every agent process, mapped to its identity and scored on reach and behaviour, with the pacify ladder in a right-click menu.
- **Detections** — the ladder for the latest containment and the signed audit trail.
- **Alignment preferences** — choose which discretionary behaviours count as misaligned (reading your files, new egress, spawning programs, …); the zero-false-positive safety signals stay locked on.
- **Mesh** — the oversight spiderweb: consensus core, the sentinel voting ring, agents on the rim colored by state, and the "many doors" panel.
- **Quarantine** — neutralized binaries, encrypted and restorable.
- **Settings** — containment authority, oversight mixing, partner status.

## The "many doors" principle

Mix networks shuffle entrances and exits so a watcher can't link them. Foldward applies this with **opposite rules for the two planes**:

- **The watched agents' traffic is never mixed** — their east-west flow *is* the net's best detection signal, so it stays fully observable. Data plane watched.
- **The oversight traffic *is* mixed** — sentinel votes and containment commands run padded with cover traffic, so a hijacked agent can't tell which sentinel flagged it or trace the consensus core. Control plane hidden.

Authentication proves *who* is talking; mixing hides *that* they are, and to whom. Time-critical containment commands skip the mix, because the kill switch must be fast.

Today the mix channel is a **design prototype**: it produces fixed-size, indistinguishable cover records from system randomness, but is not yet wired to a live network transport, and the consensus quorum runs within a single process. The "decoy actions" glamour is likewise a design, not yet implemented. These are called out so the design intent isn't read as a shipped guarantee.

## Standalone, and Route B

Foldward runs entirely on its own. When the partners are installed, it opens a port:

- **sentinel-vision** lends its *hands* once Foldward has checked it is the real program (its install folder, that only an administrator can change that folder, and version 0.5.2 or newer; standalone, Foldward never imports a package that merely has its name): it takes a contained agent's file into its hardened vault with rollback (the file is moved, not copied; if sentinel-vision refuses a file, Foldward doesn't move it either), and every containment is mirrored into its append-only plugin log, which on Windows its protection service keeps so even a program running as you cannot change or delete it. (On macOS and Linux that log is an ordinary user file until the service exists.) A copy that fails is reported and retried. Planned, not built yet: a malware verdict from sentinel-vision's `scan` used in decisions, and an automatic `block_egress` rung. Foldward's pages also appear as a tab *inside* sentinel-vision (Route B), with no dependency either way.
- **cryptomigrate** is planned as the *notary and crypto lens* (a weak-crypto scan of a flagged agent's directory, and notarised attestations). Today Foldward only detects it, without importing or running it, and signs its attestations of oversight state itself.

How Foldward plugs into sentinel-vision (the entry point, the `quarantine add` / `plugin-log` / `net block` verbs, and the Windows plugin install) is in [`docs/SENTINEL_VISION_INTEGRATION.md`](docs/SENTINEL_VISION_INTEGRATION.md).

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
- **integrations** — with no partners installed, everything degrades to Foldward's own mechanisms, never an error.

## Standards basis

- **Signatures:** [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) (ML-DSA-65) paired with Ed25519 ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final)); quarantine at rest uses AES-256-GCM ([NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)). ML-KEM (FIPS 203) is **not** used — Foldward signs, it does not do key exchange. Post-quantum transition is tracked as background by [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd).
- **AI in operational settings:** the principle that a human stays responsible and must be able to bypass, replace, and plan for the failure of the AI.
- Companion projects: [sentinel-vision](https://github.com/dylanckoldan-boop/sentinel-vision) (antimalware; hybrid ML-DSA-65 + Ed25519 signed updates) and [cryptomigrate](https://github.com/dylanckoldan-boop/Cryptomigrate) (crypto discovery, migration, and signed attestation).

## Scope and limitations

A research concept and a working v0.2, not a certified safety system.

- **It runs as you.** Foldward has your privileges, not more. A program running with your rights can interfere with it, read its signing and quarantine keys, and change its saved state (registrations, revocations, canary list, audit). Foldward checks signatures when it loads that state and reports what doesn't verify, but only sentinel-vision's protected log on Windows is out of such a program's reach.
- **Detection is heuristic and tunable.** A determined agent can evade the first-pass net.
- **Canaries are seen only while open.** Foldward checks which files agents hold open when it scans (every 2 seconds by default), so an agent that opens, reads and closes a canary between two scans can go unnoticed. The deception layers (glamour, tripwire) are not safety-rated; the guarantees live in the pacify ladder, the signed registry and the independent controls, never in the agent staying fooled.
- **Process control and firewall actions depend on OS privileges.**

## How this was built

The author designed the architecture, the four-layer model, the many-doors principle, and the module structure, and built the implementation with AI assistance (Anthropic's Claude) under that direction. Every change is run through the automated test suite, and the maintainer is responsible for all of it. Correctness is established by the test suite and the explicit invariants above, not by assertion — mirroring the companion [cryptomigrate](https://github.com/dylanckoldan-boop/Cryptomigrate) and [machineward](https://github.com/dylanckoldan-boop/machineward) projects. Foldward itself contains no AI model and sends nothing to any AI service.

Anthropic, Claude, OpenAI, LangChain, CrewAI and other product names are trademarks of their owners. They are named only to describe compatibility or what Foldward can detect; this project is not affiliated with or endorsed by them.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Dylan C. Koldan.

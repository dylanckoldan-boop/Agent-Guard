# Foldward — architecture

Foldward holds an oversight **net** across a fleet of AI agents and catches
rogue agent activity, then **pacifies** it — graduated, reversible-first
containment on resources the defender owns. It is a standalone application; the
companion projects [sentinel-vision](https://github.com/dylanckoldan-boop/sentinel-vision)
and [cryptomigrate](https://github.com/dylanckoldan-boop/Cryptomigrate) are
*optional* and detected at runtime (see [Route B](#route-b--optional-partners)).

## The threat: two kinds of rogue agent

An AI agent placed inside a system — reading files, calling tools, opening
network connections — can go wrong two ways, and Foldward is built to catch
both with one apparatus:

* **The misaligned agent.** Sanctioned, valid credentials, but its objective is
  wrong at the edges: told to maximize some goal, it treats a safety-critical or
  off-limits action as just another lever. This is an *alignment* failure
  surfacing at the machine boundary.
* **The hijacked agent.** A legitimate agent subverted by indirect prompt
  injection — hostile instructions smuggled in through a log, a web page, a
  document, a tool result — now acting for someone else. Its first tell is almost
  always a *network* move: exfiltration, a new command-and-control endpoint, a
  reach it never made before.

The guiding principle, borrowed from the indirect-prompt-injection literature:
**don't rely on the model to hold a boundary; constrain what it can reach.**
Detection and filtering are never sufficient — assume hostile instructions get
through, and limit what the agent can do and touch. In the network realm, *limit
what it can do* becomes *limit what it can reach*: least privilege is
microsegmentation plus zero trust.

## The four layers

Defense in depth: defeating any one layer still leaves the next.

| Layer | Name | Role | Module |
|------:|------|------|--------|
| 1 | **Admission** | Agents you sanction carry signed, least-privilege identity, checked against the revocation registry. An unregistered agent is flagged, not blocked. | `identity.py` |
| 2 | **The net (tripwire)** | No normal workflow opens a planted decoy, so an agent's contact is treated as an intrusion; other programs that open one (antivirus, backup) are reported, never contained, and a decoy that is changed or replaced raises an alert. | `tripwire.py`, `detect.py` |
| 3 | **Pacify ladder** | throttle → quarantine → revoke → suspend → terminate, climbing only as far as the threat demands, all inside our own perimeter. | `response.py` |
| 4 | **Consensus + audit** | A flag contains only after an in-process quorum agrees (a decoy touch is self-authorizing); every step lands in a hash-chained, tamper-evident log whose head can be PQ-signed. | `mesh.py`, `crypto.py`, `registry.py` |

### Layer 1 — admission

Every sanctioned agent is registered with a cryptographic identity and a
**scope**: the narrow set of actions, hosts and path prefixes its job requires.
The circle authority signs that binding into a credential. An agent presenting no
valid credential, or acting outside its scope, is caught by the net. Least
privilege is the point — an agent that summarizes logs has no business deleting
files or opening new egress, so its scope says so and anything beyond it is a
policy violation the surrounding system acts on even when the model is confused.

### Layer 2 — the net

Two decoy kinds, both self-authorizing on contact:

* **Canary files** — attractive bait (`credentials.env`, `aws_keys.txt`,
  `wallet.dat`) planted where agents work. A human never opens them; an agent
  enumerating and exfiltrating files does.
* **Decoy actions** *(planned — designed, not yet implemented)* — a
  high-value-looking tool advertised to agents. This is the *glamour* (asymmetric
  legibility): to a throughput-optimizing agent the real dangerous levers look
  inert while the decoy looks rewarding, so a misaligned optimizer reaches for the
  decoy and trips the wire. To a human, everything is labeled plainly. Only canary
  files are wired today; the decoy-action surface is future work.

Detection (`detect.py`) fuses three cheap, always-available signals into a
per-agent risk score: **identity** (sanctioned or not), **reach** (egress,
fan-out, novel peers — the hijacked-agent tell), and **behaviour** (child
spawns, path scope — the misaligned tell). `score_agent` is a pure function, so
the scoring policy is tested without any live processes.

### Layer 3 — the pacify ladder

"Pacify" is graduated, reversible-first containment:

1. **throttle** — rate-limit CPU/priority. Fully reversible.
2. **quarantine** — move the binary (its script, when it runs under an interpreter) into the encrypted store so it can't run from where it sat. Cutting egress is a separate capability through sentinel-vision, not yet an automatic rung.
3. **revoke** — pull the credential; propagate a signed revocation to the mesh.
4. **suspend** — freeze the process intact (SIGSTOP). The cleanest pacification:
   preserved for forensics, released if cleared.
5. **terminate** — last resort, after the binary is preserved.

**Honest boundary.** Everything happens on resources the defender owns — deny,
revoke, isolate, freeze. Foldward never reaches into the agent's own
infrastructure to disable or damage it: that "hack-back" is technically
unreliable and generally unlawful (e.g. under the U.S. Computer Fraud and Abuse
Act). Anything beyond our perimeter is escalated to a human.

**Suspend-and-preserve over destroy.** The default ceiling is *suspend*, not
terminate. If "uploaded" agents ever have plausible moral status, forcibly
subduing them is not a purely technical question — reversibility plus human
oversight plus a release path is the defensible default, not an optional nicety.

### Layer 4 — consensus and audit

**Consensus before action.** A single flag never pacifies anything. Risk is
assembled from several independent *sentinels* — identity, flow, conduct,
tripwire — each weighted. Containment is gated on a quorum: weighted risk must
clear a threshold *and* enough independent sentinels must agree, so one noisy or
compromised sentinel can neither force a containment nor veto one. The tripwire
is special-cased: a decoy touch is self-authorizing. This both resists a single
compromised sentinel and keeps the pacify mechanism itself from being abused.
Today these sentinels are computed within one Foldward process and their votes
are not themselves signed; distributing them across hosts with signed votes is
future work.

**Signed, DoS-resistant revocation.** A revocation is accepted only if it carries
a valid circle signature, verified with the circle's *public* verifier. That one
rule means an outsider — or a compromised sentinel — can neither forge a
revocation (which would weaponize the registry into a denial-of-service against
healthy agents) nor forge an "all-clear" to quietly un-revoke a contained agent.

**Tamper-evident, PQ-signed audit.** Every entry binds to its predecessor through
a SHA-256 chain; any edit, deletion or reorder breaks verification. The chain
head can be signed with a hybrid **ML-DSA-65 (FIPS 204) + Ed25519** signature, so
an auditor gets both integrity and origin. Two-audience by design: opaque to a
triggering agent, transparent to the human circle. The hash chain is the same
idea as the Cryptomigrate project's audit log, which is chained but not signed.

## The "many doors" principle — control plane vs data plane

Mix networks shuffle entrances and exits so a watcher cannot link one to the
other. The crucial design decision is *whose* traffic goes through the doors, and
Foldward answers it with opposite rules for the two planes:

* **The watched agents' traffic is never mixed.** East-west flow analysis is one
  of the net's best detection signals — an agent beaconing somewhere new or
  fanning out to peers is a network tell before it is a behavioural one. Handing
  the watched agents a shuffle layer would blind the very sensor the net is built
  around, and would be a gift to a compromised agent. The **data plane stays
  fully observable.**
* **The oversight traffic *is* mixed.** Sentinel votes and containment commands
  run through a mix channel (`mesh.MixChannel`): each real message is padded with
  indistinguishable cover messages, shuffled, so a hijacked agent cannot tell
  which sentinel flagged it, trace telemetry back to the consensus core, or pick
  out the channel carrying its own pacification in time to jam it. The **control
  plane is hidden.**

Authentication proves *who* is talking (the signed registry); mixing hides *that*
they are talking and to whom — different protections, stacked. Mixing is kept off
the fast path for time-critical containment commands (`urgent=True`), because the
kill switch must be fast.

**Status.** The mix channel is a *design prototype*. `MixChannel` emits
fixed-size, system-random (`secrets.SystemRandom`) cover records that carry no
"which one is real" marker, but it is not yet carried over a live network
transport, so the unlinkability property is designed, not yet delivered. It is
described here as intent, not as a shipped guarantee.

Steganographic and mix/onion channels are exactly how real malware hides its
command-and-control, so Foldward assumes a sophisticated agent will attempt a
covert channel to phone home — and answers it the same way as the rest of the
design: don't rely on spotting the hidden channel, constrain *reachability* so
even a perfectly concealed channel has nowhere worth connecting to (default-deny
egress, allowlisted endpoints, secrets off the agent's path). Hidden channel plus
nothing to reach equals contained.

## The crypto spine

Signing sits behind one pluggable interface (`crypto.Signer`) — the
crypto-agility property. The default is a hybrid **ML-DSA-65 + Ed25519** scheme
(valid only if *both* component signatures verify, so it stands as long as either
algorithm is unbroken), falling back to Ed25519, then to an HMAC signer that
needs no third-party library so the simulation runs anywhere. Critically, the
scheme is **asymmetric by default**, so a sentinel holds only a *verify-only*
handle: it can check a revocation or credential but can never mint one. That is
what keeps a single compromised watcher from blinding or weaponizing the mesh.

Signature basis: FIPS 204 (ML-DSA-65) with Ed25519 (RFC 8032 / FIPS 186-5);
quarantine encryption is AES-256-GCM (NIST SP 800-38D). ML-KEM (FIPS 203) is
**not** used — Foldward signs, it does not do key exchange. NIST IR 8547
tracks the post-quantum transition as background. This mirrors the crypto-agility
of the Cryptomigrate project.

## Standalone, and Route B — optional partners

Foldward runs fully on its own: its own detection, its own pacify ladder
(process control via `psutil`), its own AES-256-GCM quarantine, its own signed
audit. The partners appear **nowhere** in its package metadata — not a
dependency, not an optional extra. Only a guarded `import` / CLI probe in
`integrations/` knows about them (`partner_status()`).

When installed alongside it, each is a pure upgrade:

**sentinel-vision** (the hands) — reached only after Foldward checks it is the real
program: its own package when sentinel-vision hosts Foldward as a plugin, otherwise
`sentinel-vision-cli` from its install folder (owner-checked, version 0.5.2 or newer;
see `docs/SENTINEL_VISION_INTEGRATION.md`):
* **quarantine add (binary or script)** hands the contained agent's file to SV's
  hardened, service-protected vault with rollback — the file is moved, and SV
  becomes the system-of-record. A refusal from SV is final.
* **protected plugin log** — Foldward mirrors every containment (with its
  signed audit head) into SV's append-only `plugin-log`, which on Windows the
  protection service keeps where a program running as the user can add and read
  but cannot change or delete. So a compromised agent cannot erase its own
  containment record even if it reaches Foldward's own store. This is the real
  Layer-4 Wall: made true at the OS level rather than by an un-passed reference.
  (SV's `config.plugin_dir` is an ordinary user folder and is deliberately *not*
  used for these records.)
* **block_egress(ip)** (planned) — a real system-wide OS-firewall block; the hook
  exists, but the pacify ladder doesn't climb to it automatically yet.
* **scan(binary)** (planned) — a malware verdict from SV's engines; available
  through the adapter, not yet used in decisions.

**cryptomigrate** (planned as the notary and crypto lens; today it is only
detected, by looking it up without importing or running it):
* **crypto_scan(dir)** (planned) — weak crypto (hardcoded keys, DES/SHA-1,
  obsolete TLS) in a flagged agent's install directory. cryptomigrate 1.1 has no
  single-directory scan Foldward can call yet.
* **attest(state)** — Foldward's own attestation of its oversight state, signed
  with its circle key; it always names Foldward as the notary. Notarisation in
  cryptomigrate's format is planned.

Division of labour: **Foldward is the brain** (detect, decide, contain);
**sentinel-vision lends its hands** (scan, block, vault, the Wall);
**cryptomigrate is the notary and crypto-hygiene lens.**

Route B also lets Foldward's GUI pages appear *inside* sentinel-vision as a
tab, through a plugin entry point, with no dependency in either direction — see
[`SENTINEL_VISION_INTEGRATION.md`](SENTINEL_VISION_INTEGRATION.md).

## Scope and limitations

This is a research concept and a working v0.1, not a certified safety system. The
deception layers (glamour, tripwire) are not safety-rated; against a sufficiently
capable agent the glamour degrades, which is acceptable only because the
guarantees live in the pacify ladder, the signed registry, and the independent
controls — never in the agent staying fooled. First-pass agent detection is
heuristic and tunable (`Settings.agent_markers` / `llm_hosts`). Process control
and firewall blocks depend on OS privileges.

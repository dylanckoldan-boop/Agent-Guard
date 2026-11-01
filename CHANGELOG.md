# Changelog

All notable changes to Foldward are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Audit finding IDs are in brackets.

## [0.2.1] - 2026-11-01

### Security
- Changing a canary's times or permissions before reading it no longer disarms it. 0.2.0's
  fix for forged markers also required the canary's change time to be unchanged, so one
  `touch` or `chmod` let a rogue agent read the bait unseen. A canary now counts as long as it
  is a regular file at a path this install planted, and a canary that is changed, replaced or
  deleted raises an alert, because reading one changes none of that [AG-N07].

## [0.2.0] - 2026-10-31

This release closes the findings of the 31 October 2026 audit and makes Foldward's
claims match the code. Needs sentinel-vision 0.5.2 or newer for the partner features (released
together with it); older versions are reported by `status` and not used.

### Security
- A process is never exempt from detection because of its name: an operating-system
  daemon such as `ssh-agent` is skipped only when its executable is the system's own
  root-owned (or System32) file. A rogue agent launched as `ssh-agent`, or from a renamed
  copy of the interpreter, is checked like any other [AG-N01].
- Containment freezes the agent first when it climbs to suspend, and quarantine reads
  only an existing regular file within a size and time limit, so an agent can no longer
  stall its own containment with a FIFO or a device. A relative script path is resolved
  against the agent's own working directory, never Foldward's [AG-N02].
- Canaries are recognised only from the list of files this install planted (path, file
  identity and change time), saved so later runs recognise them; a marker line copied into
  another file is ignored. A registered agent that opens a canary is flagged for you, not
  contained automatically [AG-N03].
- Saved registrations and revocations are checked against the circle signature when they
  load; a sanctioned identity is bound to its process's PID **and** start time, and key and
  state files are owner-only from the moment they exist [AG-N04].
- A damaged audit log is kept aside and reported instead of being replaced silently [AG-N05].
- Canary contact by programs that aren't agents (antivirus, backup) is reported, never
  contained [AG-A02].
- Shared runtimes (Java, .NET, PowerShell, shells, launchers, in addition to Python and
  Node) are never quarantined; the app asks before "Quarantine binary" [AG-A05].
- Start-up warns when post-quantum signing is unavailable; `cryptography` 47 or newer is
  required [AG-A09].

### sentinel-vision integration
- sentinel-vision is found only in its install folder (`/opt/SentinelVision`,
  `/Applications/SentinelVision.app/Contents/MacOS`, `Program Files\Sentinel Vision`),
  checked for an administrator-only owner and version 0.5.2 or newer; standalone, a package
  merely named `sentinel_vision` is never imported. `foldward-cli status` shows the path and
  version, or why it wasn't trusted [AG-A04, AG-C04, INT-02, INT-03].
- Calls follow sentinel-vision's published contract: `--` before file names and addresses,
  only a public IP reaches the firewall, `scan` exit 1 means threats found, quarantine ids
  are checked, and a refusal (exit 3) is final — Foldward no longer moves a file
  sentinel-vision refused [AG-F08, INT-01, INT-04]. The contract is replayed in
  `tests/test_sentinel_vision_contract.py`.
- A scan answer is "clean" only when a file was scanned and none couldn't be read, and the
  protected-log check says "intact" only when every log was checked and each answer agrees
  with its exit code; anything else is "unknown", never a pass [INT-01].
- A containment record that can't be copied to sentinel-vision's protected log is reported
  and retried [INT-05].
- Plugin pages are labelled "Foldward · …" (their `ag_*` keys are unchanged).

### cryptomigrate
- cryptomigrate is detected by looking it up, never by importing it, so a module that merely
  has its name is never run inside Foldward [AG-A04].
- Its weak-crypto scan and notarisation are marked planned (the scan called an entry point
  cryptomigrate doesn't have), and attestations always name Foldward as the notary: they are
  signed with Foldward's circle key whether or not cryptomigrate is installed [AG-C01].

### Supply chain and release
- A release can be started from Actions → Release → Run workflow → Publish, which creates the
  tag on `main` itself; pushing a `vX.Y.Z` tag still works. Each release is also uploaded to
  PyPI through trusted publishing once its publisher is set up, so no PyPI token is stored.
- CI installs from hash-locked requirements (`requirements/*.lock`), runs ruff with its
  security rules, and fails on a known-vulnerable locked dependency [AG-A10].
- New `release.yml`: a `vX.Y.Z` tag builds the wheel and source archive with
  `SHA256SUMS.txt` and publishes a GitHub release after your approval. Install and update
  commands name a release tag, never the moving `main` branch [INT-06].
- The website deploys only after its checks pass [AG-B03].

### Website and documents
- Partner features that aren't built (a malware verdict from sentinel-vision, an automatic
  egress block) are marked planned, and "defeating any one layer still leaves the next" is
  replaced by what the layers really do [AG-C01, AG-D02, AG-E05].
- New accessibility statement, linked from every page [AG-E03]; every page shows the version
  and date, checked against the package [AG-C06]; the privacy policy is re-dated for the
  update check [AG-N06]; `SECURITY.md` no longer shows a placeholder contact [AG-E07].
- Stale integration notes updated [INT-08].

### Upgrading
- Agents registered by PID before 0.2.0 must be registered again (registrations are now bound
  to the process start time).
- Run `foldward-cli canaries --dir …` again for each folder with canaries: existing canary
  files are adopted into the planted list, never overwritten.

## [0.1.0] - 2026-10-26

First release, then named Agent Guard.

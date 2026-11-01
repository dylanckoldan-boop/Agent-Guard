# Route B — integrating with sentinel-vision

This page documents how Foldward plugs into sentinel-vision from Foldward's side.
sentinel-vision's own contract is in that project's
[`docs/PLUGINS.md`](https://github.com/dylanckoldan-boop/sentinel-vision/blob/main/docs/PLUGINS.md),
and its machine-readable form, [`docs/plugin-contract.json`](https://github.com/dylanckoldan-boop/sentinel-vision/blob/main/docs/plugin-contract.json),
is copied into this repository as `tests/data/sentinel_vision_contract.json` and replayed
by `tests/test_sentinel_vision_contract.py`. Foldward 0.2.0 is tested against
sentinel-vision 0.5.2 and needs 0.5.1 or newer.

The rule in both directions: **neither project depends on the other.** Foldward
imports nothing from sentinel-vision at module scope; sentinel-vision imports
nothing from Foldward. They meet at a Python entry point and a few command-line verbs.
With sentinel-vision absent, Foldward runs fully standalone; with Foldward
absent, sentinel-vision behaves exactly as before.

## 0. Finding the real sentinel-vision

Foldward acts on whatever it believes is sentinel-vision, so it checks before it
trusts (AG-A04, INT-02, INT-03):

| How Foldward runs | What it uses |
|---|---|
| Inside sentinel-vision (the app loaded it as a plugin and called `register()`) | `sentinel_vision`, the host's own already-loaded package, for the protected log; the command-line tool for the other verbs |
| On its own | `sentinel-vision-cli` from the install folder only — `Program Files\Sentinel Vision` (asked from Windows, not read from `%ProgramFiles%`), `/Applications/SentinelVision.app/Contents/MacOS`, or `/opt/SentinelVision` — never `$PATH`, never a package that merely has the name |

On macOS and Linux the tool and every folder up to the install folder must belong
to root and be closed to writes by group and others, as sentinel-vision's install
steps leave them. The tool must report version 0.5.1 or newer. `foldward-cli status`
shows the path and version it found, or why it didn't trust what it found.

## 1. A page inside sentinel-vision

Foldward declares the entry point sentinel-vision looks for:

```toml
[project.entry-points."sentinel_vision.plugins"]
foldward = "foldward.gui.plugin:register"
```

`register()` (in `foldward/gui/plugin.py`) returns one descriptor per page,
each with a `key`, a sidebar `label` and a `factory(ctx)` that returns a QWidget.

- **Keys are namespaced `ag_*`** (kept from the Agent Guard name, because
  sentinel-vision documents them). sentinel-vision skips any plugin page whose key
  collides with one of its built-ins, so Foldward exposes `ag_overview`, `ag_net`,
  `ag_detections`, `ag_mesh`, `ag_quarantine`, `ag_settings`, labelled `Foldward · …`.
- **It uses the host's descriptor when hosted.** `register()` returns
  `sentinel_vision.plugin_api.PluginPage` instances when that import succeeds
  (it only does because sentinel-vision is the caller), and its own duck-typed
  descriptor otherwise.

Foldward runs its **own** engine inside the host, writing its own settings,
quarantine and keys under the user's data folder, so the pages behave identically
to standalone; the host lends its window, tray and notifications.

### Installing the plugin (Windows)

The installed Windows app loads plugins only from an administrator-only folder and
checks their permissions before loading. Install a **tagged release** from an
administrator terminal, with a Python matching the app (3.12):

```
py -3.12 -m pip install --target "C:\Program Files\Sentinel Vision\plugins\foldward" "foldward @ git+https://github.com/dylanckoldan-boop/Foldward@v0.2.0"
```

Install a tag from the repository, never the moving `main` branch and never a
package from PyPI: `agent-guard` there is an unrelated project, and `foldward`
isn't claimed there by this project. sentinel-vision asks for a one-time
approval before loading a new or changed plugin; `sentinel-vision-cli plugins`
lists what was found and why anything was refused. After upgrading from Agent
Guard, remove the old `plugins\agent-guard` folder (sentinel-vision 0.5.2 skips it
when Foldward is installed, and says so).

## 2. Handing a contained agent's file to the vault

The pacify ladder's quarantine rung, when sentinel-vision is present, calls:

```
sentinel-vision-cli quarantine add --reason "<text>" -- PATH
```

PATH is the agent's own binary, or — when it runs under a shared runtime (Python,
Node, Java, .NET, PowerShell, a shell) — its script, resolved against the agent's
working directory; never the runtime itself. sentinel-vision **moves** the file
(encrypts it into the vault and deletes the original as the calling user, so it can
never remove a file the user couldn't), prints only the new 32-character item id and
exits 0.

| sentinel-vision answers | Foldward does |
|---|---|
| exit 0 and a 32-character id | records it as quarantined by sentinel-vision |
| exit 0 without a valid id | reports it and does **not** quarantine the file again (sentinel-vision may hold it) |
| exit 3 — refused on purpose (an operating-system file, sentinel-vision's own files, a link or other non-regular file; since 0.5.2) | reports the refusal and stops: Foldward never moves the file itself instead (INT-04) |
| exit 2, or no answer | treats sentinel-vision as unavailable and uses its own AES-256-GCM vault, which applies the same refusals and fails when the original can't be removed |

## 3. Records nothing else can erase — the real Wall

Foldward mirrors every containment into sentinel-vision's protected, append-only
plugin log:

```
sentinel-vision-cli plugin-log append foldward --json '{"event":"pacify", ...}'
```

On Windows the protection service keeps this log where a program running as the
user can add and read entries but **cannot change or delete them**; each entry is
hash-chained to its predecessor and `plugin-log verify` reports whether the chain
is intact (exit 0 intact, 1 broken). `core.py` appends a record — carrying the
signed audit head — on every `pacify()`. A copy that fails is reported to the
operator and retried at the next scan (INT-05).

New records are written under the log name **`foldward`**. `plugin_log_verify`
checks both `foldward` and the pre-rename **`agent-guard`** log, so containment
records written before the rename are still verified and never orphaned. The
answer is "intact" only when both logs were checked (a log that was never written
counts as intact with 0 entries) and each answer agrees with its exit code; one
that can't be checked, or contradicts itself, makes the answer "unknown".

## 4. Blocking egress (planned)

`Containment.block_egress(host)`, when sentinel-vision is present, calls
`sentinel-vision-cli net block -- IP` for a public address only (anything else is
refused before sentinel-vision is called). This is a containment **hook** for a
future automatic "cut egress" rung — the pacify ladder doesn't climb to it yet.

## 5. A malware verdict (planned)

`SentinelVisionAdapter.scan(path)` runs `sentinel-vision-cli scan --no-quarantine
--json -- PATH` and reads exit 1 (with a positive `threats` count) as malware, and
exit 0 as clean only when at least one file was scanned and none couldn't be read.
Anything else, including an answer whose count disagrees with its exit code, is
"unknown". It isn't used in Foldward's decisions yet.

## 6. The contract, tested on both sides

sentinel-vision publishes these command shapes, exit codes and example answers as
`docs/plugin-contract.json` and tests its real tool against it. Foldward keeps a
copy in `tests/data/sentinel_vision_contract.json`; `tests/test_sentinel_vision_contract.py`
checks every command the adapter runs against the contract and replays every
example answer through the adapter. A new answer in the contract fails that test
until Foldward decides what to do with it. To update the copy, take the file from
sentinel-vision; set `SENTINEL_VISION_REPO` to a sentinel-vision checkout to have
the test compare them.

## Graceful degradation

With sentinel-vision absent, every one of these degrades to Foldward's own
mechanism — its own quarantine, its own hash-chained + PQ-signed audit, a recorded
intent for egress blocks — and never raises. The adapter's probes return
`(False, "not installed")` and `make_containment` returns the base ladder. This is
covered by `tests/test_integrations.py`.

# Route B — integrating with sentinel-vision

Route B is **implemented in sentinel-vision 0.4.1**. This page documents how Foldward plugs into it from Foldward's side; sentinel-vision's own contract is in
that project's [`docs/PLUGINS.md`](https://github.com/dylanckoldan-boop/sentinel-vision/blob/main/docs/PLUGINS.md).

The rule in both directions: **neither project depends on the other.** Foldward
imports nothing from sentinel-vision at module scope; sentinel-vision imports
nothing from Foldward. They meet at a Python entry point and a few CLI verbs.
With sentinel-vision absent, Foldward runs fully standalone; with Foldward
absent, sentinel-vision behaves exactly as before.

## 1. A page inside sentinel-vision

Foldward declares the entry point sentinel-vision looks for:

```toml
[project.entry-points."sentinel_vision.plugins"]
foldward = "foldward.gui.plugin:register"
```

`register()` (in `foldward/gui/plugin.py`) returns one descriptor per page,
each with a `key`, a sidebar `label` and a `factory(ctx)` that returns a QWidget.
Two details matter for sentinel-vision 0.4.1:

- **Keys are namespaced `ag_*`.** sentinel-vision skips any plugin page whose key
  collides with one of its built-ins (it has `overview`, `quarantine`,
  `settings`, …), so Foldward exposes `ag_overview`, `ag_net`, `ag_detections`,
  `ag_mesh`, `ag_quarantine`, `ag_settings`, labelled `AG · …`.
- **It uses the host's descriptor when hosted.** `register()` returns
  `sentinel_vision.plugin_api.PluginPage` instances when that import succeeds
  (it only does because sentinel-vision is the caller), and its own duck-typed
  descriptor otherwise. This is not a dependency — the import lives inside
  `register()`, which only sentinel-vision calls.

Foldward runs its **own** engine inside the host (sentinel-vision does not
provide it), writing its own settings/quarantine/key under the user's data
directory, so the pages behave identically to standalone; the host lends its
window, tray and notifications. sentinel-vision calls each page's `refresh()`
when shown and periodically while visible, which Foldward's pages already have.

### Installing the plugin (Windows)

The installed Windows app loads plugins only from an administrator-only folder and
checks their ACLs before loading. Install from an administrator terminal, with a
Python matching the app (3.12):

```
py -3.12 -m pip install --target "C:\Program Files\Sentinel Vision\plugins\foldward" "git+https://github.com/dylanckoldan-boop/Foldward"
```

Install from the repository, not from PyPI: the name `foldward` on PyPI is an
unrelated project and is not this software. This installs Foldward's core and
its dependencies the app doesn't already
bundle (PySide6 comes from sentinel-vision itself). sentinel-vision asks for a
one-time approval before loading a new or changed plugin. For pip/source installs
on any platform, the entry point is discovered normally with no extra step.
`sentinel-vision-cli plugins` lists what was found and why anything was refused.

## 2. Handing a neutralized binary to the vault

The pacify ladder's quarantine rung, when sentinel-vision is present, calls:

```
sentinel-vision-cli quarantine add PATH --reason "<text>"
```

When the agent runs under an interpreter (`python agent.py`, `node agent.js`),
Foldward passes the **script**, never the shared interpreter, so containment
can't neutralise every Python or Node process on the machine. In 0.4.1
sentinel-vision **moves** the file (encrypts it into the vault like an
automatic detection and deletes the original), prints only the new item id and
exits 0; on any problem it exits 2 and nothing changes. It refuses non-regular
files, operating-system files and sentinel-vision's own files. `--source` defaults
to `foldward` on sentinel-vision's side, so Foldward does not pass it. If the
verb is unavailable, Foldward keeps the binary in its own AES-256-GCM store
instead (`integrations/sentinel_vision.py` handles the fallback).

## 3. Records nothing else can erase — the real Wall

This replaces the earlier idea of a "protected directory." `config.plugin_dir` is
an ordinary user folder and is **not** used for security records. Instead, Foldward mirrors every containment into sentinel-vision's protected, append-only
plugin log:

```
sentinel-vision-cli plugin-log append foldward --json '{"event":"pacify", ...}'
```

On Windows the protection service keeps this log where a program running as the
user can add and read entries but **cannot change or delete them**; each entry is
hash-chained to its predecessor and `plugin-log verify` reports whether the chain
is intact. So a compromised agent cannot erase its own containment record even if
it reaches Foldward's own store. `core.py` appends a record — carrying the
signed audit head — on every `pacify()`, through
`SentinelVisionAdapter.plugin_log_append` (in-process `plugin_api.plugin_log` when
importable, else the CLI).

New records are written under the log name **`foldward`**. `plugin_log_verify`
checks both `foldward` and the pre-rename **`agent-guard`** log, so containment
records written before the rename are still verified and never orphaned. (The
`agent-guard` name is retired on the sentinel-vision side as part of the same
coordinated release; see the rename note in `docs/NAME_CLEARANCE.md`.)

## 4. Blocking egress

`Containment.block_egress(host)`, when sentinel-vision is present, calls
`sentinel-vision-cli net block IP`, which adds inbound/outbound rules to the system
firewall (public addresses only; needs admin/root). This is a containment **hook**,
available for a future automatic "cut egress" rung — the pacify ladder
(throttle → quarantine → revoke → suspend → terminate) does not climb to it on its
own yet.

## Graceful degradation

With sentinel-vision absent, every one of these degrades to Foldward's own
mechanism — its own quarantine, its own hash-chained + PQ-signed audit, a recorded
intent for egress blocks — and never raises. The adapter's probes return
`(False, "not installed")` and `make_containment` returns the base ladder. This is
covered by `tests/test_integrations.py`.

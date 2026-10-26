# Route B — the sentinel-vision integration spec

**Audience: whoever maintains [sentinel-vision](https://github.com/dylanckoldan-boop/sentinel-vision).**
This is the complete, self-contained instruction list for making sentinel-vision
and Agent Guard interlock. You do **not** need Agent Guard's source to implement
it — only the contract below.

## Ground rules

1. **Every change here is additive and backward-compatible.** With Agent Guard
   absent, sentinel-vision must behave exactly as it does today. Nothing below
   removes or alters existing behaviour.
2. **sentinel-vision takes no dependency on Agent Guard.** You never `import
   agent_guard`. You expose seams; Agent Guard plugs into them. Discovery is by
   entry point and by a documented CLI verb.
3. **Scope.** Do this work only in the sentinel-vision repository. Three seams,
   in priority order: (1) a plugin host so Agent Guard appears as a tab; (2) a
   `quarantine add` verb so Agent Guard can hand you binaries; (3) optional —
   a protected-store handle and a `net block` verb.

---

## Seam 1 — plugin host (so Agent Guard appears as a tab)

**Goal:** when both apps are installed, an "Agent Guard" section appears in
sentinel-vision's sidebar, hosting Agent Guard's pages inside your shell — with
no import of Agent Guard.

**The contract Agent Guard already implements.** Agent Guard declares, in its own
`pyproject.toml`:

```toml
[project.entry-points."sentinel_vision.plugins"]
agent_guard = "agent_guard.gui.plugin:register"
```

`register()` returns a list of objects with three attributes:

```python
page.key      # str  — unique id, e.g. "ag_net"
page.label    # str  — sidebar text, e.g. "Agent Guard"
page.factory  # callable(host_ctx) -> QWidget
```

`factory(host_ctx)` returns a `QWidget` to drop into your stack. `host_ctx` is
**duck-typed**: Agent Guard uses only `host_ctx.notify(title, text, level)` and
`host_ctx.navigate(key)` if present. Your existing `AppContext`
(`gui/pages/base.py`) already provides both, so **pass your `self.ctx`
unchanged.**

**What to add — in `gui/app.py`, `MainWindow.__init__`,** right after the
existing NAV loop that builds pages (the `for key, text, cls in NAV:` block):

```python
# --- optional plugins (e.g. Agent Guard). No-op if none are installed. ---
self._load_plugins()
```

and add the method:

```python
def _load_plugins(self) -> None:
    """Discover and mount pages contributed by installed plugins
    (entry-point group 'sentinel_vision.plugins'). Never fails the app:
    a broken plugin is logged and skipped."""
    from importlib.metadata import entry_points
    try:
        eps = entry_points(group="sentinel_vision.plugins")
    except Exception:
        return
    for ep in eps:
        try:
            pages = ep.load()()            # register() -> list of page descriptors
            for p in pages:
                widget = p.factory(self.ctx)   # self.ctx is your AppContext
                self.pages[p.key] = widget
                self.stack.addWidget(widget)
                btn = QPushButton(p.label)
                btn.setObjectName("nav")
                btn.setCheckable(True)
                btn.setCursor(Qt.PointingHandCursor)
                btn.clicked.connect(lambda _c=False, k=p.key: self.navigate(k))
                self._nav_group.addButton(btn)      # your QButtonGroup
                self.buttons[p.key] = btn
                self._sidebar_layout.addWidget(btn)  # the layout holding nav buttons
        except Exception as exc:
            log.warning("plugin %s failed to load: %s", getattr(ep, "name", "?"), exc)
```

Adapt the three names in the last three lines (`self._nav_group`,
`self._sidebar_layout`) to whatever your `__init__` actually calls the
`QButtonGroup` and the sidebar `QVBoxLayout` — in the current code they are the
local `group` and `sl`; promote them to `self.` so `_load_plugins` can reach
them. Insert the plugin buttons *before* the final `sl.addStretch(1)` so they sit
with the other nav items.

**Promote two names to a documented plugin API.** Agent Guard's pages are
`QWidget`s and need nothing from you, but so that *future* plugins can subclass
your page base, add a one-line re-export module `sentinel_vision/plugin_api.py`:

```python
"""Stable surface for sentinel-vision plugins."""
from sentinel_vision.gui.pages.base import AppContext, Page  # re-exported for plugins
__all__ = ["AppContext", "Page"]
```

That's the whole of Seam 1. It is ~25 lines and touches only `gui/app.py` plus
one new tiny module.

---

## Seam 2 — `quarantine add` (so Agent Guard can hand you binaries)

**Goal:** Agent Guard neutralizes a rogue agent and hands its binary to
sentinel-vision's hardened, service-protected vault with rollback, making
sentinel-vision the system-of-record for contained artifacts.

Agent Guard calls this **through your CLI** (process-isolated, stable):

```bash
sentinel-vision-cli quarantine add <path> --reason "<text>"
```

**What to add:**

1. **A public method on `Quarantine`** (in `quarantine.py`): `add_external(path:
   str, reason: str = "", source: str = "agent-guard") -> str`. It should encrypt
   and store the file exactly as your automatic quarantine does (AES-256-GCM,
   per-chunk integrity, owner-only), record `reason`/`source` in the item's
   metadata, and return the new quarantine id. Use your existing quarantine
   internals — this is a thin public entry point, not new crypto. On Windows with
   the protection service, route it through the service the same way your
   automatic quarantine already does.

2. **A CLI verb** in `cli.py`, under the existing `quarantine` subcommand (which
   already has `list` and `restore`):

   ```
   quarantine add <path> [--reason TEXT]
   ```
   It calls `Quarantine.add_external(path, reason)` and prints the new id. Exit
   `0` on success, `2` on error, consistent with your other verbs. Validate the
   path exists and is a regular file before storing.

**Fallback behaviour (already handled on Agent Guard's side):** if this verb is
absent (older sentinel-vision), Agent Guard keeps the binary in its own
AES-256-GCM store and notes that sentinel-vision's vault was unavailable — so
shipping Seam 2 later, independently, is safe.

---

## Seam 3 — optional (protected store + net block)

Both are nice-to-have, both additive.

1. **Protected-store handle — the real Layer-4 Wall.** Expose a path under
   sentinel-vision's admin-only service directory that another local tool may use
   for its own tamper-evident records. Add to `config.py`:

   ```python
   def plugin_dir(name: str) -> Path:
       """A protected, service-guarded subdirectory for a named plugin."""
       d = sub_dir("plugins") / name
       d.mkdir(parents=True, exist_ok=True)
       return d
   ```

   On Windows, ensure it lands under the service-protected
   `%ProgramData%\SentinelVision\Service` tree (admin/SYSTEM-only ACL) like your
   vault, not the user folder. Agent Guard, when it sees this, stores its audit +
   revocation registry there so a compromised user-level agent can't erase its
   own containment record.

2. **`net block <ip>` CLI verb.** You already block criminal netblocks in the OS
   firewall via `network/firewall.py` (`block_ip`). Expose it as a CLI verb:

   ```
   sentinel-vision-cli net block <ip>
   ```
   Validate the IP (reuse your existing validation — reject private/loopback),
   call `block_ip`, print the result. This gives Agent Guard's "cut egress" rung
   OS-level teeth even over the process-isolated CLI path.

---

## The signed handoff record (reference, no code needed now)

For a looser, cross-process coupling (and for your own audit), Agent Guard can
drop a signed JSON record in a shared `handoff/` directory when it contains an
agent. The format, if you ever want to ingest it:

```json
{
  "format": "agent-guard-handoff/1",
  "at": 1730000000.0,
  "agent_id": "rogue-1",
  "action": "pacified",
  "rung": "suspend",
  "binary_sha256": "…",
  "reason": "touched decoy credentials.env",
  "signer_ref": "hybrid:…",
  "signature": "hybrid:…"
}
```

The signature is a hybrid ML-DSA-65 + Ed25519 signature over the canonical JSON
(all fields except `signature`), verifiable with Agent Guard's published circle
public key. You do not need to implement this for Seams 1–3; it is here so the
format is on record.

---

## Acceptance checklist

- [ ] With Agent Guard **not** installed, sentinel-vision starts and behaves
      identically to before (plugin loop finds nothing, logs nothing alarming).
- [ ] With Agent Guard installed, an "Agent Guard" tab appears and its pages
      render inside sentinel-vision's window, using its tray and notifications.
- [ ] `sentinel-vision-cli quarantine add <file> --reason test` stores the file
      in the vault and prints an id; `quarantine list` then shows it; `restore`
      round-trips it.
- [ ] A malformed plugin cannot crash sentinel-vision (the `try/except` in
      `_load_plugins` holds).
- [ ] No `import agent_guard` anywhere in sentinel-vision.
- [ ] Existing sentinel-vision tests still pass; new tests cover `add_external`
      and the `quarantine add` / `net block` verbs.

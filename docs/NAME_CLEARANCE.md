# Name clearance — "Foldward"

Recorded 31 October 2026. **This is due-diligence, not legal advice.** Before any
trademark filing or commercial use, run a formal search (USPTO, EUIPO, WIPO Global
Brand Database) or consult a trademark attorney.

## The name

**Foldward** — from *fold* (a sheepfold: an enclosure that both protects and
contains a flock) and *ward* (to guard; and a protected enclosure or a charge
under guardianship). It reads as "guardian of the fold": a protective perimeter
for the fleet of agents it watches and, when one goes rogue, contains. It pairs in
spirit with the companion project **sentinel-vision** (watchful protection)
without reusing a crowded or trademarked term.

## Why the project was renamed (from "Agent Guard")

The former name collided badly in its own market:

- **PyPI**: the distribution name `agent-guard` is already taken by an unrelated
  project (an operational-monitoring library for CrewAI), so this project could
  not publish under it and its install docs had pointed at the wrong package.
- **Same-market products** using "Agent Guard" / "AgentGuard": CyberArk Agent
  Guard, AppOmni AgentGuard, Akto AgentGuard, and GoPlus AgentGuard — all in
  AI-agent security. Same name, same market invites confusion and complaints.

## Checks performed for "Foldward" (31 Oct 2026)

| Source | Result |
|---|---|
| PyPI (`/pypi/foldward/json`) | 404 — **available** |
| npm (`/foldward`) | 404 — **available** |
| Web / market search ("foldward … software security company product") | No product, company, or trademark hits found |
| GitHub | Repo lives in the owner's namespace (`dylanckoldan-boop/Foldward`) |

Single dictionary words considered (redoubt, parapet, picket, cordon, warren,
weir, bulwark, aegis) were all already taken on PyPI and npm, and several brush
against existing security products (WatchGuard, SentinelOne, Keepnet Labs,
Palisade Research), which is why a distinctive coined compound was chosen.

## Still recommended before wide release

- A formal trademark search in the jurisdictions that matter to you.
- Reserve the PyPI name with trusted publishing and the GitHub repo name.
- Optionally secure a domain (e.g. `foldward.io`/`.com`) — not checked here.

## Still to do (owner)

- **Claim `foldward` on PyPI** (checked 1 Nov 2026: still unregistered). Until it is
  claimed, anyone can publish a package under the name, and a `pip install foldward`
  typed by a person — or invented by an AI assistant — would install it. The release
  workflow uploads each release to PyPI through trusted publishing (no token stored
  anywhere) once you add the pending publisher listed in `docs/REPO_SETTINGS.md`; a
  pending publisher doesn't reserve the name, the first upload does. Until then
  every install command names a tagged release of this repository.

## Integration note (sentinel-vision)

The rename was released in step with sentinel-vision 0.5.1: Foldward writes its
records to the `foldward` plugin log, sentinel-vision files `quarantine add`
requests under `foldward` by default, and both still read and verify the old
`agent-guard` log, so records from before the rename aren't orphaned.

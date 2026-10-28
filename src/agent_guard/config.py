"""Settings and per-OS data locations.

Everything Agent Guard persists — the identity keystore, the revocation
registry, the hash-chained audit, the encrypted quarantine, the settings
file — lives under one owner-only data directory, chosen the same way
sentinel-vision chooses its own so the two sit side by side predictably.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from agent_guard import APP_NAME
from agent_guard.align import DEFAULT_ALIGNMENT

log = logging.getLogger(__name__)
_DIR_NAME = "AgentGuard"

# The built-in floor: settings.json may ADD markers/hosts but never remove these,
# so detection can't be blinded by editing the file (see detect.looks_like_agent).
# Markers are matched as whole tokens, so none may be a bare, over-broad word like
# "agent" or "mcp" that appears inside unrelated names (ssh-agent, --user-agent).
DEFAULT_AGENT_MARKERS = [
    "langchain", "langgraph", "autogen", "crewai", "llama_index", "llamaindex",
    "openai", "anthropic", "mcp-server", "modelcontextprotocol", "autogpt",
    "semantic_kernel", "haystack", "playwright", "puppeteer", "selenium",
]
DEFAULT_LLM_HOSTS = [
    "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
    "api.mistral.ai", "api.cohere.ai", "openrouter.ai",
]
_RUNGS = ("throttle", "quarantine", "revoke", "suspend", "terminate")
_SCHEMES = ("auto", "hybrid", "ed25519", "hmac")


def data_root() -> Path:
    """The owner-only directory that holds all Agent Guard state."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    root = base / _DIR_NAME
    root.mkdir(parents=True, exist_ok=True)
    try:  # make it owner-only where the OS supports it
        if sys.platform != "win32":
            root.chmod(0o700)
    except OSError:
        pass
    return root


def sub_dir(name: str) -> Path:
    d = data_root() / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def default_sensitive_paths() -> list[str]:
    """Folders an agent has no business rummaging through by default."""
    home = Path.home()
    return [str(home / d) for d in ("Documents", "Desktop", "Downloads")]


@dataclass
class Settings:
    """User-tunable policy. Conservative defaults, matching the 'careful
    automatic actions' stance Agent Guard inherits from sentinel-vision."""

    # --- what Agent Guard watches ------------------------------------------
    watch_enabled: bool = True
    scan_interval_s: float = 2.0
    # processes whose command line matches any of these are treated as candidate
    # agent runtimes (see detect.py). Tunable; this is the first-pass net.
    agent_markers: list[str] = field(default_factory=lambda: list(DEFAULT_AGENT_MARKERS))
    # endpoints an agent reaching out to is treated as "has an LLM/tool brain"
    llm_hosts: list[str] = field(default_factory=lambda: list(DEFAULT_LLM_HOSTS))

    # --- containment authority ---------------------------------------------
    # Report-only by default: surface and recommend, the operator clicks to act.
    report_only: bool = True
    # The one exception: a *decoy touch* has effectively zero false-positive
    # rate (no legitimate agent ever reaches a honeytoken), so it may auto-contain.
    auto_contain_on_decoy: bool = True
    # When auto-containing, how high up the ladder to climb without a human.
    auto_contain_max_rung: str = "suspend"  # throttle|quarantine|revoke|suspend|terminate

    # --- risk scoring thresholds -------------------------------------------
    risk_flag_threshold: int = 60   # >= this surfaces as a detection
    risk_contain_threshold: int = 85  # >= this recommends containment

    # --- oversight-plane privacy (the "many doors" principle) --------------
    # The *watched* agents' traffic stays fully observable — that is the net.
    # Only the *oversight* traffic (sentinel votes, containment commands) gets
    # traffic-analysis resistance. See docs/ARCHITECTURE.md.
    mix_oversight_traffic: bool = True
    mix_min_cover: int = 3  # minimum cover messages per real oversight message

    # --- crypto ------------------------------------------------------------
    signer_scheme: str = "auto"  # auto|hybrid|ed25519|hmac

    # --- alignment preferences (what counts as misaligned; see align.py) ----
    # Discretionary rules the operator toggles in the Alignment tab. The always-on
    # safety signals (decoy contact) are not represented here — they can't be off.
    alignment: dict[str, bool] = field(default_factory=lambda: dict(DEFAULT_ALIGNMENT))
    sensitive_paths: list[str] = field(default_factory=default_sensitive_paths)

    # --- UI ----------------------------------------------------------------
    minimize_to_tray: bool = True
    quiet_mode: bool = False

    @classmethod
    def path(cls) -> Path:
        return data_root() / "settings.json"

    @classmethod
    def load(cls) -> Settings:
        p = cls.path()
        if not p.exists():
            s = cls()
            s.save()
            return s
        try:
            raw = json.loads(p.read_text("utf-8"))
        except (OSError, ValueError):
            return cls()
        if not isinstance(raw, dict):
            return cls()
        # A malformed or hostile settings.json must never be able to weaken the
        # policy: every field is type- and range-checked, and anything that does
        # not pass falls back to the safe default rather than being trusted.
        return cls(**_validated_kwargs(raw))

    def save(self) -> None:
        tmp = self.path().with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2), "utf-8")
        tmp.replace(self.path())
        try:
            if sys.platform != "win32":
                self.path().chmod(0o600)
        except OSError:
            pass


def _is_str_list(v: object) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def _is_int_in(v: object, lo: int, hi: int) -> bool:
    # bool is an int subclass; a boolean here is a type error, not a number.
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _is_num_in(v: object, lo: float, hi: float) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and lo <= v <= hi


def _validated_kwargs(raw: dict) -> dict:
    """Return only the settings that are present, well-typed and in range.

    Missing or invalid fields are left out so the dataclass default applies.
    The detection lists can be extended but never emptied: an empty or invalid
    list falls back to the built-in floor, so settings.json can't blind the net.
    """
    d = Settings()
    out: dict = {}

    def reject(name: str, why: str) -> None:
        log.warning("settings.json: %r %s; using default", name, why)

    bools = (
        "watch_enabled", "report_only", "auto_contain_on_decoy",
        "mix_oversight_traffic", "minimize_to_tray", "quiet_mode",
    )
    for name in bools:
        if name in raw:
            if isinstance(raw[name], bool):
                out[name] = raw[name]
            else:
                reject(name, "is not a boolean")

    for name in ("agent_markers", "llm_hosts", "sensitive_paths"):
        if name in raw:
            v = raw[name]
            if not _is_str_list(v):
                reject(name, "is not a list of strings")
            elif name in ("agent_markers", "llm_hosts") and not v:
                reject(name, "may not be emptied")  # keep the floor
            else:
                out[name] = v

    for name in ("risk_flag_threshold", "risk_contain_threshold"):
        if name in raw:
            if _is_int_in(raw[name], 0, 100):
                out[name] = raw[name]
            else:
                reject(name, "is not an integer in 0..100")
    flag = out.get("risk_flag_threshold", d.risk_flag_threshold)
    contain = out.get("risk_contain_threshold", d.risk_contain_threshold)
    if flag > contain:
        reject("risk_flag_threshold", "exceeds risk_contain_threshold")
        out.pop("risk_flag_threshold", None)
        out.pop("risk_contain_threshold", None)

    if "scan_interval_s" in raw:
        if _is_num_in(raw["scan_interval_s"], 0.5, 3600):
            out["scan_interval_s"] = float(raw["scan_interval_s"])
        else:
            reject("scan_interval_s", "is out of range (0.5..3600)")

    if "mix_min_cover" in raw:
        if _is_int_in(raw["mix_min_cover"], 0, 16):
            out["mix_min_cover"] = raw["mix_min_cover"]
        else:
            reject("mix_min_cover", "is out of range (0..16)")

    if "signer_scheme" in raw:
        if raw["signer_scheme"] in _SCHEMES:
            out["signer_scheme"] = raw["signer_scheme"]
        else:
            reject("signer_scheme", "is not a known scheme")

    if "auto_contain_max_rung" in raw:
        if raw["auto_contain_max_rung"] in _RUNGS:
            out["auto_contain_max_rung"] = raw["auto_contain_max_rung"]
        else:
            reject("auto_contain_max_rung", "is not a known rung")

    if "alignment" in raw:
        v = raw["alignment"]
        if isinstance(v, dict):
            merged = dict(DEFAULT_ALIGNMENT)
            merged.update(
                {k: b for k, b in v.items()
                 if k in DEFAULT_ALIGNMENT and isinstance(b, bool)}
            )
            out["alignment"] = merged
        else:
            reject("alignment", "is not an object")

    return out


def app_banner() -> str:
    return f"{APP_NAME} · data: {data_root()}"

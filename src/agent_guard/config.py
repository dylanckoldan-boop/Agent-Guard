"""Settings and per-OS data locations.

Everything Agent Guard persists — the identity keystore, the revocation
registry, the hash-chained audit, the encrypted quarantine, the settings
file — lives under one owner-only data directory, chosen the same way
sentinel-vision chooses its own so the two sit side by side predictably.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from agent_guard import APP_NAME

_DIR_NAME = "AgentGuard"


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


@dataclass
class Settings:
    """User-tunable policy. Conservative defaults, matching the 'careful
    automatic actions' stance Agent Guard inherits from sentinel-vision."""

    # --- what Agent Guard watches ------------------------------------------
    watch_enabled: bool = True
    scan_interval_s: float = 2.0
    # processes whose command line matches any of these are treated as candidate
    # agent runtimes (see detect.py). Tunable; this is the first-pass net.
    agent_markers: list[str] = field(
        default_factory=lambda: [
            "langchain", "langgraph", "autogen", "crewai", "llama_index", "llamaindex",
            "openai", "anthropic", "mcp", "modelcontextprotocol", "agent", "autogpt",
            "semantic_kernel", "haystack", "playwright", "puppeteer", "selenium",
        ]
    )
    # endpoints an agent reaching out to is treated as "has an LLM/tool brain"
    llm_hosts: list[str] = field(
        default_factory=lambda: [
            "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
            "api.mistral.ai", "api.cohere.ai", "openrouter.ai",
        ]
    )

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

    # --- UI ----------------------------------------------------------------
    minimize_to_tray: bool = True
    quiet_mode: bool = False

    @classmethod
    def path(cls) -> Path:
        return data_root() / "settings.json"

    @classmethod
    def load(cls) -> "Settings":
        p = cls.path()
        if not p.exists():
            s = cls()
            s.save()
            return s
        try:
            raw = json.loads(p.read_text("utf-8"))
        except (OSError, ValueError):
            return cls()
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in raw.items() if k in known})

    def save(self) -> None:
        tmp = self.path().with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2), "utf-8")
        tmp.replace(self.path())
        try:
            if sys.platform != "win32":
                self.path().chmod(0o600)
        except OSError:
            pass


def app_banner() -> str:
    return f"{APP_NAME} · data: {data_root()}"

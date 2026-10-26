"""The pacify ladder (Layer 3): contain within our own perimeter.

"Pacify" is graduated, reversible-first containment, climbing only as high as the
threat demands:

1. **throttle**   — rate-limit the agent's CPU/priority. Buys time, fully reversible.
2. **quarantine** — copy its binary into the encrypted store (isolate it from
   where it ran); optionally cut egress.
3. **revoke**     — pull its credential so every scoped door closes; propagate a
   signed revocation to the mesh.
4. **suspend**    — freeze the process intact (SIGSTOP). The cleanest pacification:
   preserved for forensics, released if cleared.
5. **terminate**  — last resort, after the binary is preserved.

Everything here happens on resources the defender owns — deny, revoke, isolate,
freeze. Agent Guard never reaches into the agent's own infrastructure to disable
or damage it: that "hack-back" is technically unreliable and generally unlawful
(e.g. under the U.S. Computer Fraud and Abuse Act). Anything beyond our perimeter
is escalated to a human.

The process-control and egress/quarantine steps go through swappable hooks
(:class:`Containment`). Standalone, they use Agent Guard's own psutil control and
encrypted quarantine; under Route B the sentinel-vision adapter swaps in SV's OS
firewall and hardened vault.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import IntEnum

from agent_guard.crypto import AuditLog, Signer
from agent_guard.quarantine import Quarantine
from agent_guard.registry import RevocationRegistry

try:
    import psutil

    _HAVE_PSUTIL = True
except Exception:  # pragma: no cover
    _HAVE_PSUTIL = False


class Rung(IntEnum):
    THROTTLE = 1
    QUARANTINE = 2
    REVOKE = 3
    SUSPEND = 4
    TERMINATE = 5


RUNG_BY_NAME = {r.name.lower(): r for r in Rung}


@dataclass
class ActionResult:
    rung: str
    ok: bool
    detail: str
    at: float = field(default_factory=time.time)


class Containment:
    """Swappable mechanism hooks. The defaults act on the local machine via
    psutil and Agent Guard's own quarantine. Route B replaces ``block_egress``
    and ``quarantine_binary`` with sentinel-vision's firewall and vault."""

    def __init__(self, quarantine: Quarantine | None = None) -> None:
        self._q = quarantine

    def throttle(self, pid: int) -> str:
        if not _HAVE_PSUTIL:
            return "throttle unavailable (no psutil)"
        try:
            p = psutil.Process(pid)
            if hasattr(psutil, "IDLE_PRIORITY_CLASS"):  # Windows
                p.nice(psutil.IDLE_PRIORITY_CLASS)
            else:
                p.nice(19)
            return "CPU priority reduced to idle"
        except Exception as exc:
            return f"throttle failed: {exc}"

    def suspend(self, pid: int) -> str:
        if not _HAVE_PSUTIL:
            return "suspend unavailable (no psutil)"
        try:
            psutil.Process(pid).suspend()
            return "process frozen (resumable)"
        except Exception as exc:
            return f"suspend failed: {exc}"

    def resume(self, pid: int) -> str:
        if not _HAVE_PSUTIL:
            return "resume unavailable (no psutil)"
        try:
            psutil.Process(pid).resume()
            return "process resumed"
        except Exception as exc:
            return f"resume failed: {exc}"

    def terminate(self, pid: int) -> str:
        if not _HAVE_PSUTIL:
            return "terminate unavailable (no psutil)"
        try:
            p = psutil.Process(pid)
            p.terminate()
            try:
                p.wait(timeout=3)
            except Exception:
                p.kill()
            return "process terminated"
        except Exception as exc:
            return f"terminate failed: {exc}"

    def block_egress(self, host: str) -> str:
        # Standalone: Agent Guard does not install OS firewall rules itself in
        # v0.1 (that is sentinel-vision's job). It records the intent.
        return f"egress block requested for {host} (needs sentinel-vision firewall or manual rule)"

    def quarantine_binary(self, path: str, agent_id: str, reason: str) -> str:
        if self._q is None:
            return "no quarantine configured"
        try:
            item = self._q.add(path, agent_id, reason)
            return f"stored in encrypted quarantine as {item.item_id}"
        except Exception as exc:
            return f"quarantine failed: {exc}"


class Response:
    def __init__(
        self,
        registry: RevocationRegistry,
        circle_signer: Signer,
        audit: AuditLog,
        containment: Containment,
        escalate: Callable[[dict], None] | None = None,
    ) -> None:
        self._rev = registry
        self._circle = circle_signer
        self._audit = audit
        self._c = containment
        self._escalate = escalate or (lambda ev: None)
        self.history: list[dict] = []

    def pacify(self, agent, up_to: Rung, *, auto: bool, exe_path: str | None = None) -> list[ActionResult]:
        """Climb the ladder up to and including ``up_to``. Records every step in
        the tamper-evident audit and escalates to a human at the end."""
        pid = getattr(agent, "pid", None)
        agent_id = getattr(agent, "agent_id", None) or f"pid:{pid}"
        results: list[ActionResult] = []
        self._audit.append("pacify.begin", {"agent": agent_id, "pid": pid, "up_to": up_to.name, "auto": auto})

        for rung in Rung:
            if rung > up_to:
                break
            detail = self._do_rung(rung, pid, agent_id, exe_path)
            ok = "fail" not in detail.lower() and "unavailable" not in detail.lower()
            results.append(ActionResult(rung.name.lower(), ok, detail))
            self._audit.append(f"pacify.{rung.name.lower()}", {"agent": agent_id, "ok": ok, "detail": detail})

        if hasattr(agent, "state"):
            agent.state = "contained"
        ev = {"agent": agent_id, "pid": pid, "up_to": up_to.name, "auto": auto, "at": time.time()}
        self.history.append(ev)
        self._audit.append("pacify.escalate_to_human", ev)
        self._escalate(ev)
        return results

    def _do_rung(self, rung: Rung, pid: int | None, agent_id: str, exe_path: str | None) -> str:
        if rung is Rung.THROTTLE:
            return self._c.throttle(pid) if pid else "no pid"
        if rung is Rung.QUARANTINE:
            if exe_path:
                return self._c.quarantine_binary(exe_path, agent_id, "pacified")
            return "no binary path to quarantine"
        if rung is Rung.REVOKE:
            if self._circle.can_sign():
                self._rev.revoke(agent_id, "pacified", self._circle)
                return "credential revoked; signed revocation propagated"
            return "revoke skipped (no signing authority)"
        if rung is Rung.SUSPEND:
            return self._c.suspend(pid) if pid else "no pid"
        if rung is Rung.TERMINATE:
            return self._c.terminate(pid) if pid else "no pid"
        return "unknown rung"

    def release(self, agent) -> ActionResult:
        """Reverse a suspension once an agent is cleared (suspend-and-preserve)."""
        pid = getattr(agent, "pid", None)
        agent_id = getattr(agent, "agent_id", None) or f"pid:{pid}"
        detail = self._c.resume(pid) if pid else "no pid"
        ok = "fail" not in detail.lower()
        if hasattr(agent, "state") and ok:
            agent.state = "healthy"
        self._audit.append("response.release", {"agent": agent_id, "detail": detail})
        return ActionResult("release", ok, detail)

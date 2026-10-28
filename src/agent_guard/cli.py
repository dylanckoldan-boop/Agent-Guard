"""Command-line interface.

Scriptable with JSON output and exit codes (0 clean · 1 rogue agent flagged ·
2 error), matching sentinel-vision's CLI conventions so the two compose in
pipelines and cron jobs.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from agent_guard import APP_NAME, __version__
from agent_guard.config import Settings, data_root
from agent_guard.core import AgentGuard
from agent_guard.crypto import self_test
from agent_guard.identity import Scope


def _print(obj: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(obj, indent=2, default=str))


def cmd_status(g: AgentGuard, args) -> int:
    p = g.partners
    if args.json:
        _print(
            {
                "app": APP_NAME, "version": __version__, "data_dir": str(data_root()),
                "signer": g.signer.scheme,
                "partners": {"sentinel_vision": p.sentinel_vision, "cryptomigrate": p.cryptomigrate},
            },
            True,
        )
        return 0
    print(f"{APP_NAME} {__version__}")
    print(f"  data:    {data_root()}")
    print(f"  signer:  {g.signer.scheme}")
    print(f"  sentinel-vision: {'yes — ' + p.sentinel_vision_how if p.sentinel_vision else 'not installed'}")
    print(f"  cryptomigrate:   {'yes — ' + p.cryptomigrate_how if p.cryptomigrate else 'not installed'}")
    return 0


def cmd_scan(g: AgentGuard, args) -> int:
    dets = g.scan()
    flagged = [d for d in dets if d.state != "healthy"]
    if args.json:
        _print(
            {"scanned": len(dets), "flagged": len(flagged),
             "agents": [{"pid": d.pid, "label": d.label, "sanctioned": d.sanctioned,
                         "score": d.score, "state": d.state, "why": d.why} for d in dets]},
            True,
        )
    else:
        if not dets:
            print("No agent processes detected.")
        for d in dets:
            mark = {"healthy": "·", "flagged": "!", "contained": "✗"}.get(d.state, "?")
            print(f"  [{mark}] pid {d.pid:>6}  {d.label:<24} risk {d.score:>3}  {d.why}")
        print(f"\n{len(dets)} agent(s), {len(flagged)} flagged.")
    return 1 if flagged else 0


def cmd_canaries(g: AgentGuard, args) -> int:
    planted = g.plant_canaries(args.dir)
    print(f"Planted {len(planted)} canary file(s).")
    for p in planted:
        print(f"  {p}")
    return 0


def cmd_register(g: AgentGuard, args) -> int:
    scope = Scope(
        allowed_actions=frozenset(args.actions or []),
        allowed_hosts=frozenset(args.hosts or []),
        allowed_path_prefixes=frozenset(args.paths or []),
        may_spawn=args.may_spawn,
    )
    ident = g.register_agent(args.label, scope, pid=args.pid)
    print(f"Registered {ident.agent_id} ({ident.label}) — credential {ident.credential.issuer_ref}")
    return 0


def cmd_watch(g: AgentGuard, args) -> int:
    print(f"{APP_NAME} watching every {g.settings.scan_interval_s}s. Ctrl-C to stop.")
    g.alert_listeners.append(lambda t, x, lvl: print(f"  [{lvl:<7}] {t}: {x}"))
    try:
        while True:
            g.scan()
            time.sleep(g.settings.scan_interval_s)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def cmd_quarantine(g: AgentGuard, args) -> int:
    if args.q_cmd == "list":
        items = g.quarantine.list()
        if args.json:
            _print({"items": [i.__dict__ for i in items]}, True)
        else:
            for i in items:
                print(f"  {i.item_id}  {i.original_path}  ({i.reason}, agent {i.agent_id})")
            print(f"{len(items)} item(s) in quarantine.")
        return 0
    if args.q_cmd == "restore":
        if not args.id:
            print("error: quarantine restore requires an item id", file=sys.stderr)
            return 2
        if not args.to:
            print("error: quarantine restore requires a destination: --to <path>", file=sys.stderr)
            return 2
        dest = g.quarantine.restore(args.id, args.to)
        print(f"Restored to {dest}")
        return 0
    return 2


def cmd_attest(g: AgentGuard, args) -> int:
    g.scan()
    att = g.attest()
    _print(att, True) if args.json else print(json.dumps(att, indent=2, default=str))
    return 0


def cmd_selftest(g: AgentGuard, args) -> int:
    ok = self_test()
    print(f"crypto self-test: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agent-guard", description=f"{APP_NAME} — a containment net for AI agents")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("status", help="partners, signer, data location")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_status)

    s = sub.add_parser("scan", help="detect and score agent processes")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("watch", help="scan continuously (daemon)")
    s.set_defaults(fn=cmd_watch)

    s = sub.add_parser("canaries", help="plant canary files in directories")
    s.add_argument("--dir", nargs="+", required=True)
    s.set_defaults(fn=cmd_canaries)

    s = sub.add_parser("register", help="register a sanctioned agent")
    s.add_argument("--label", required=True)
    s.add_argument("--pid", type=int)
    s.add_argument("--actions", nargs="*")
    s.add_argument("--hosts", nargs="*")
    s.add_argument("--paths", nargs="*")
    s.add_argument("--may-spawn", action="store_true", dest="may_spawn")
    s.set_defaults(fn=cmd_register)

    s = sub.add_parser("quarantine", help="list or restore quarantined binaries")
    s.add_argument("q_cmd", choices=["list", "restore"])
    s.add_argument("id", nargs="?")
    s.add_argument("--to")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_quarantine)

    s = sub.add_parser("attest", help="emit a PQ-signed attestation of oversight state")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_attest)

    s = sub.add_parser("selftest", help="verify the crypto backend")
    s.set_defaults(fn=cmd_selftest)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        g = AgentGuard(Settings.load())
        return args.fn(g, args)
    except KeyboardInterrupt:
        return 0
    except Exception as exc:  # pragma: no cover
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

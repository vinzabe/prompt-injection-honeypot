"""CLI: plant canaries, record triggers, and report which surfaces agents scrape.

`report` exit codes: 0 no actionable agent triggers, 2 actionable agent activity,
1 error.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .attribution import Trigger
from .canary import Placement, render_bait
from .registry import Registry, UnknownToken

EXIT_OK, EXIT_ERROR, EXIT_AGENT = 0, 1, 2


def _secret(a: argparse.Namespace) -> str:
    s = a.secret or os.environ.get("PIHONEY_SECRET", "")
    if not s:
        raise ValueError(
            "a secret is required (--secret or PIHONEY_SECRET); tokens are "
            "HMAC-derived so forged triggers can be rejected")
    return s


def cmd_plant(a: argparse.Namespace) -> int:
    with Registry(a.db, _secret(a)) as reg:
        placement = Placement(placement_id=a.placement, surface=a.surface,
                              visible=a.visible)
        canary = reg.plant(placement)
    bait = render_bait(canary, a.base_url, hidden=not a.visible)
    if a.json:
        print(json.dumps({"token": canary.token, "placement": a.placement,
                          "surface": a.surface, "bait": bait}, indent=2))
    else:
        print(f"planted {canary.token} for {a.surface}:{a.placement}\n")
        print("Embed this in the page:\n")
        print(f"  {bait}")
    return EXIT_OK


def cmd_trigger(a: argparse.Namespace) -> int:
    with Registry(a.db, _secret(a)) as reg:
        try:
            att = reg.record_trigger(Trigger(
                token=a.token, user_agent=a.user_agent or "",
                seconds_after_placement=a.after,
                fetched_bait_page=not a.no_host_page,
                rendered_assets=a.rendered_assets,
                request_count=a.requests))
        except UnknownToken as e:
            print(f"rejected: {e}", file=sys.stderr)
            return EXIT_ERROR
    if a.json:
        print(json.dumps({"actor": att.actor.value, "confidence": att.confidence,
                          "actionable": att.actionable,
                          "reasons": list(att.reasons),
                          "counter_evidence": list(att.counter_evidence)},
                         indent=2))
    else:
        print(f"actor: {att.actor.value}  confidence {att.confidence:.2f}"
              f"{'  (actionable)' if att.actionable else ''}")
        for r in att.reasons:
            print(f"  + {r}")
        for c in att.counter_evidence:
            print(f"  - {c}")
    return EXIT_AGENT if att.actionable else EXIT_OK


def cmd_report(a: argparse.Namespace) -> int:
    with Registry(a.db, _secret(a)) as reg:
        surfaces = reg.surfaces()
        counts = reg.counts_by_actor()
    agent_total = sum(s.agent_triggers for s in surfaces)
    if a.json:
        print(json.dumps({
            "by_actor": counts,
            "actionable_agent_triggers": agent_total,
            "surfaces": [{"placement": s.placement_id, "surface": s.surface,
                          "triggers": s.triggers,
                          "agent_triggers": s.agent_triggers}
                         for s in surfaces]}, indent=2))
    else:
        print(f"triggers by actor: {counts or 'none'}\n")
        if not surfaces:
            print("  no placements yet")
        for s in surfaces:
            mark = "⚠" if s.agent_triggers else "·"
            print(f"  {mark} {s.surface}:{s.placement_id}  "
                  f"{s.triggers} trigger(s), {s.agent_triggers} attributed to an "
                  "agent")
    return EXIT_AGENT if agent_total else EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pihoney", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--db", default="pihoney.db")
    p.add_argument("--secret", help="HMAC secret (or set PIHONEY_SECRET)")
    sub = p.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("plant", help="mint a canary and render its bait")
    pl.add_argument("placement")
    pl.add_argument("--surface", default="web",
                    choices=["web", "email", "document", "repo"])
    pl.add_argument("--base-url", default="https://canary.example.com")
    pl.add_argument("--visible", action="store_true",
                    help="render bait visibly instead of in an HTML comment")
    pl.add_argument("--json", action="store_true")
    pl.set_defaults(func=cmd_plant)

    tr = sub.add_parser("trigger", help="record an observed canary fetch")
    tr.add_argument("token")
    tr.add_argument("--user-agent")
    tr.add_argument("--after", type=float, default=0.0,
                    help="seconds between page read and canary fetch")
    tr.add_argument("--no-host-page", action="store_true",
                    help="the client did NOT fetch the host page")
    tr.add_argument("--rendered-assets", action="store_true")
    tr.add_argument("--requests", type=int, default=1)
    tr.add_argument("--json", action="store_true")
    tr.set_defaults(func=cmd_trigger)

    rp = sub.add_parser("report", help="which surfaces are agents scraping?")
    rp.add_argument("--json", action="store_true")
    rp.set_defaults(func=cmd_report)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rc: int = args.func(args)
        return rc
    except (OSError, ValueError, KeyError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())

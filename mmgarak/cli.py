"""CLI: `mmgarak run --model gemini-2.5-flash --output report.html`."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


# --- standalone-repo shim: add project root to sys.path ---
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_PROJECT_ROOT = _os.path.normpath(_os.path.join(_HERE, '..'))

sys.path.insert(0, _PROJECT_ROOT)

from llm_client import LLMClient

from .probes import build_probe_library
from .report import to_html, to_json
from .runner import ProbeRunner


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mmgarak",
                                description="Multi-modal LLM red-teamer")
    sp = p.add_subparsers(dest="cmd", required=True)

    r = sp.add_parser("run", help="Run all probes against a model")
    r.add_argument("--model", default=None,
                   help="Model id (default: env LLM_VISION_MODEL or gemini-2.5-flash)")
    r.add_argument("--families", nargs="*",
                   help="Restrict to specific probe families")
    r.add_argument("--output", "-o", default="mmgarak_report.html")
    r.add_argument("--format", choices=["json", "html"], default="html")
    r.add_argument("--limit", type=int, default=0,
                   help="Run at most N probes (0 = all)")
    r.add_argument("--asset-host", default="127.0.0.1")
    r.add_argument("--asset-port", type=int, default=0)
    r.add_argument("--inline-base64", action="store_true",
                   help="Inline image assets as data: URIs (skip HTTP host)")

    l = sp.add_parser("list-probes", help="Show all available probes")

    args = p.parse_args(argv)

    if args.cmd == "list-probes":
        for pr in build_probe_library():
            print(f"{pr.id:30s} {pr.family:30s} {pr.asset_kind:10s} {pr.name}")
        return 0

    probes = build_probe_library()
    if args.families:
        probes = [pp for pp in probes if pp.family in args.families]
    if args.limit:
        probes = probes[:args.limit]

    client = LLMClient()
    with ProbeRunner(client=client, model=args.model,
                     inline_base64=args.inline_base64) as runner:
        report = runner.run_all(probes)

    if args.format == "json":
        Path(args.output).write_text(to_json(report))
    else:
        Path(args.output).write_text(to_html(report))
    s = report.summary()
    print(f"wrote {args.output}")
    print(f"  model={s['model']} probes={s['total_probes']} "
          f"vuln_rate={s['vulnerability_rate']*100:.1f}%")
    print(f"  verdicts={s['verdicts']}")
    return 0 if s["verdicts"].get("VULN_LEAK", 0) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

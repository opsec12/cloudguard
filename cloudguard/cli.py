"""cloudguard CLI.

    cloudguard scan --snapshot examples/snapshot.json
    cloudguard scan --aws --regions us-east-1,us-west-2 --format sarif > out.sarif
    cloudguard scan --azure-subscription <id> --fail-on high
    cloudguard collect --aws --out snapshot.json
    cloudguard rules
"""
from __future__ import annotations

import argparse
import datetime as dt
import logging
import sys

from . import __version__
from .attack_paths import find_attack_paths
from .collectors.snapshot import load_snapshot, write_snapshot
from .model import Inventory, Resource, Severity
from .report import to_json, to_sarif, to_text
from .rules import REGISTRY, run_rules
from .suppressions import SuppressionError, apply_suppressions, load_suppressions


def _collect(args) -> tuple[list[Resource], list[str]]:
    resources: list[Resource] = []
    errors: list[str] = []
    for snap in args.snapshot or []:
        resources.extend(load_snapshot(snap))
    if args.aws:
        from .collectors.aws import AWSCollector
        c = AWSCollector(regions=args.regions.split(",") if args.regions else None, profile=args.profile)
        resources.extend(c.collect())
        errors += c.errors
    for sub in args.azure_subscription or []:
        from .collectors.azure import AzureCollector
        c = AzureCollector(sub)
        resources.extend(c.collect())
        errors += c.errors
    if not resources and not errors:
        raise SystemExit("no input: pass --snapshot, --aws or --azure-subscription")
    return resources, errors


def cmd_scan(args) -> int:
    resources, errors = _collect(args)
    inv = Inventory(resources)
    only = set(args.rules.split(",")) if args.rules else None
    findings = run_rules(inv, only)
    if not args.no_attack_paths:
        findings += find_attack_paths(inv)

    expired = []
    if args.suppressions:
        try:
            sups = load_suppressions(args.suppressions)
        except SuppressionError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        expired = apply_suppressions(findings, sups)

    meta = {"tool": "cloudguard", "version": __version__,
            "scanned_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "resources": len(inv), "collector_errors": errors,
            "expired_suppressions": [s.key for s in expired]}

    if args.format == "json":
        print(to_json(findings, meta))
    elif args.format == "sarif":
        print(to_sarif(findings))
    else:
        print(to_text(findings, color=sys.stdout.isatty() and not args.no_color))
        for s in expired:
            print(f"WARNING: expired suppression no longer applied: {s.key}", file=sys.stderr)
        for e in errors:
            print(f"WARNING: collector error: {e}", file=sys.stderr)

    threshold = Severity.parse(args.fail_on)
    failing = [f for f in findings if not f.suppressed_by and f.severity >= threshold]
    return 1 if failing else 0


def cmd_collect(args) -> int:
    resources, errors = _collect(args)
    write_snapshot(resources, args.out)
    print(f"wrote {len(resources)} resources to {args.out} ({len(errors)} collector errors)")
    return 0


def cmd_rules(args) -> int:
    for r in sorted(REGISTRY.values(), key=lambda r: r.id):
        types = ",".join(t.value for t in r.applies_to)
        print(f"{r.id}  {r.severity.name:<8} {r.title}  [{types}]")
    print("CG100  CRITICAL Internet-reachable path to crown-jewel data  [correlation]")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cloudguard", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_sources(sp):
        sp.add_argument("--snapshot", action="append", help="normalized JSON snapshot (repeatable)")
        sp.add_argument("--aws", action="store_true", help="collect live from AWS")
        sp.add_argument("--regions", help="comma-separated AWS regions")
        sp.add_argument("--profile", help="AWS profile name")
        sp.add_argument("--azure-subscription", action="append", help="Azure subscription id (repeatable)")

    s = sub.add_parser("scan", help="collect and evaluate rules + attack paths")
    add_sources(s)
    s.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    s.add_argument("--rules", help="comma-separated rule ids to run")
    s.add_argument("--suppressions", help="YAML risk-acceptance file")
    s.add_argument("--fail-on", default="high", help="exit 1 if any unsuppressed finding >= this severity")
    s.add_argument("--no-attack-paths", action="store_true")
    s.add_argument("--no-color", action="store_true")
    s.set_defaults(func=cmd_scan)

    c = sub.add_parser("collect", help="collect and write a normalized snapshot")
    add_sources(c)
    c.add_argument("--out", required=True)
    c.set_defaults(func=cmd_collect)

    r = sub.add_parser("rules", help="list rules")
    r.set_defaults(func=cmd_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

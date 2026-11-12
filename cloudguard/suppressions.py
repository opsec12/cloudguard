"""Risk-acceptance (suppression) handling.

A suppression must name a rule, a resource glob, an owner, a reason and an
expiry date. Expired suppressions stop suppressing *and* are reported, so
"temporary" exceptions can't silently become permanent. This is the
mechanism that lets a security team roll out a new control across broad
infrastructure without blocking teams that need time to remediate.

    suppressions:
      - rule: CG010
        resource: "sg-0bastion*"
        owner: infra-access
        reason: "Bastion SSH; migrating to IAP, ticket SEC-1234"
        expires: 2026-12-31
"""
from __future__ import annotations

import datetime as dt
import fnmatch
from dataclasses import dataclass
from pathlib import Path

import yaml

from .model import Finding
from .rules import REGISTRY

MAX_SUPPRESSION_DAYS = 180


@dataclass
class Suppression:
    rule: str
    resource: str
    owner: str
    reason: str
    expires: dt.date

    @property
    def key(self) -> str:
        return f"{self.rule}:{self.resource} (owner={self.owner}, expires={self.expires})"

    def matches(self, f: Finding) -> bool:
        return (self.rule in ("*", f.rule_id)) and fnmatch.fnmatchcase(f.resource_id, self.resource)


class SuppressionError(ValueError):
    pass


def load_suppressions(path: str | Path, today: dt.date | None = None) -> list[Suppression]:
    today = today or dt.date.today()
    raw = yaml.safe_load(Path(path).read_text()) or {}
    out = []
    for i, s in enumerate(raw.get("suppressions", [])):
        missing = {"rule", "resource", "owner", "reason", "expires"} - s.keys()
        if missing:
            raise SuppressionError(f"suppression #{i} missing {sorted(missing)}")
        if s["rule"] != "*" and s["rule"] not in REGISTRY and s["rule"] != "CG100":
            raise SuppressionError(f"suppression #{i} references unknown rule {s['rule']}")
        expires = s["expires"] if isinstance(s["expires"], dt.date) else dt.date.fromisoformat(str(s["expires"]))
        if (expires - today).days > MAX_SUPPRESSION_DAYS:
            raise SuppressionError(
                f"suppression #{i} ({s['rule']}) expires {expires}; max allowed is {MAX_SUPPRESSION_DAYS} days")
        if s["rule"] == "CG100" or s["rule"] == "*":
            if s["resource"] in ("*", "**"):
                raise SuppressionError(f"suppression #{i} is a blanket suppression; scope it to a resource")
        out.append(Suppression(s["rule"], s["resource"], s["owner"], s["reason"], expires))
    return out


def apply_suppressions(findings: list[Finding], sups: list[Suppression],
                       today: dt.date | None = None) -> list[Suppression]:
    """Mark matching findings suppressed. Returns the list of expired suppressions."""
    today = today or dt.date.today()
    active = [s for s in sups if s.expires >= today]
    expired = [s for s in sups if s.expires < today]
    for f in findings:
        for s in active:
            if s.matches(f):
                f.suppressed_by = s.key
                break
    return expired

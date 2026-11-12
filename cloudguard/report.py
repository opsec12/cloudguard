"""Output formats: human table, JSON (for pipelines), SARIF 2.1.0 (for code-scanning UIs)."""
from __future__ import annotations

import json
from collections import Counter

from . import __version__
from .model import Finding, Severity
from .rules import REGISTRY

_COLORS = {Severity.CRITICAL: "\033[1;41m", Severity.HIGH: "\033[31m", Severity.MEDIUM: "\033[33m",
           Severity.LOW: "\033[36m", Severity.INFO: "\033[2m"}
_RESET = "\033[0m"


def to_text(findings: list[Finding], color: bool = True) -> str:
    lines = []
    active = [f for f in findings if not f.suppressed_by]
    for f in sorted(active, key=lambda f: (-f.severity, f.rule_id, f.resource_id)):
        sev = f"{f.severity.name:<8}"
        if color:
            sev = f"{_COLORS[f.severity]}{sev}{_RESET}"
        lines.append(f"{sev} {f.rule_id}  {f.title}")
        lines.append(f"         resource : {f.resource_id} ({f.provider})")
        lines.append(f"         detail   : {f.detail}")
        lines.append(f"         fix      : {f.remediation}")
        lines.append("")
    counts = Counter(f.severity.name for f in active)
    summary = ", ".join(f"{counts.get(s.name, 0)} {s.name.lower()}" for s in sorted(Severity, reverse=True))
    sup = sum(1 for f in findings if f.suppressed_by)
    lines.append(f"Summary: {summary}; {sup} suppressed")
    return "\n".join(lines)


def to_json(findings: list[Finding], meta: dict) -> str:
    return json.dumps({"meta": meta, "findings": [f.to_dict() for f in findings]}, indent=2)


_SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
                Severity.LOW: "note", Severity.INFO: "note"}


def to_sarif(findings: list[Finding]) -> str:
    rules = [{"id": r.id, "name": r.fn.__name__, "shortDescription": {"text": r.title},
              "help": {"text": r.remediation},
              "properties": {"security-severity": str(2.0 + 2 * int(r.severity))}}
             for r in REGISTRY.values()]
    rules.append({"id": "CG100", "name": "attack_path",
                  "shortDescription": {"text": "Internet-reachable path to crown-jewel data"},
                  "properties": {"security-severity": "10.0"}})
    results = []
    for f in findings:
        res = {"ruleId": f.rule_id, "level": _SARIF_LEVEL[f.severity],
               "message": {"text": f.detail},
               "partialFingerprints": {"cloudguard/v1": f.fingerprint},
               "locations": [{"logicalLocations": [{"fullyQualifiedName": f.resource_id,
                                                    "kind": "resource"}]}]}
        if f.suppressed_by:
            res["suppressions"] = [{"kind": "external", "justification": f.suppressed_by}]
        results.append(res)
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "cloudguard", "version": __version__, "rules": rules}},
                  "results": results}]}, indent=2)

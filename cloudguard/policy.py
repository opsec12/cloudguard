"""Small helpers for reasoning about IAM-style policy documents and CIDRs.

These are deliberately conservative: when a statement is ambiguous
(NotAction, conditions we don't evaluate) we treat it as granting access,
because a false positive is cheaper than a missed path to model weights.
"""
from __future__ import annotations

import fnmatch
import ipaddress
from typing import Any, Iterable

ADMIN_PORTS = {
    22: "SSH", 3389: "RDP", 6443: "Kubernetes API", 2379: "etcd",
    2380: "etcd peer", 10250: "kubelet", 5432: "PostgreSQL", 3306: "MySQL",
    6379: "Redis", 9200: "Elasticsearch", 8888: "Jupyter",
}

OPEN_CIDRS = {"0.0.0.0/0", "::/0", "*", "Internet", "Any"}


def is_open_cidr(cidr: str) -> bool:
    if cidr in OPEN_CIDRS:
        return True
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    # Anything broader than a /8 is effectively the internet for our purposes.
    return net.prefixlen <= 8 and not net.is_private


def port_range_covers(from_port: int, to_port: int, port: int) -> bool:
    if from_port in (-1, None) or to_port in (-1, None):  # "all traffic"
        return True
    return from_port <= port <= to_port


def _as_list(v: Any) -> list[str]:
    if v is None:
        return []
    return [v] if isinstance(v, str) else list(v)


def _matches_any(patterns: Iterable[str], value: str) -> bool:
    value = value.lower()
    return any(fnmatch.fnmatchcase(value, p.lower()) for p in patterns)


def statement_allows(stmt: dict[str, Any], action: str, resource_arn: str) -> bool:
    if stmt.get("Effect", "Allow") != "Allow":
        return False
    if "NotAction" in stmt:
        action_ok = not _matches_any(_as_list(stmt["NotAction"]), action)
    else:
        action_ok = _matches_any(_as_list(stmt.get("Action")), action)
    if not action_ok:
        return False
    if "NotResource" in stmt:
        return not _matches_any(_as_list(stmt["NotResource"]), resource_arn)
    return _matches_any(_as_list(stmt.get("Resource", "*")), resource_arn)


def policy_allows(statements: list[dict[str, Any]], action: str, resource_arn: str) -> bool:
    """Explicit Deny wins, then any Allow. Conditions are ignored (conservative)."""
    for s in statements:
        if s.get("Effect") == "Deny" and _matches_any(_as_list(s.get("Action")), action) \
                and _matches_any(_as_list(s.get("Resource", "*")), resource_arn):
            return False
    return any(statement_allows(s, action, resource_arn) for s in statements)


def is_admin_statement(stmt: dict[str, Any]) -> bool:
    if stmt.get("Effect", "Allow") != "Allow" or "Condition" in stmt:
        return False
    actions = _as_list(stmt.get("Action"))
    resources = _as_list(stmt.get("Resource"))
    return any(a in ("*", "*:*") for a in actions) and "*" in resources

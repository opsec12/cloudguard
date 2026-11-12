"""Attack-path correlation.

Single-resource rules produce a lot of MEDIUM noise. What actually matters is
whether those weaknesses *chain*: an internet-reachable VM whose instance role
can assume another role that can read the bucket holding model weights is a
CRITICAL incident waiting to happen, even if each hop alone looks moderate.

We build a directed graph:

    INTERNET -> compute (public IP + open ingress)
    compute  -> identity (instance profile / managed identity)
    identity -> identity (sts:AssumeRole permitted AND target trusts source)
    identity -> crown jewel (read on sensitive storage, or decrypt on its key)

then BFS from INTERNET to every crown jewel and report the shortest path.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from .model import Finding, Inventory, Resource, ResourceType, Severity
from .policy import is_open_cidr, policy_allows

INTERNET = "INTERNET"

READ_ACTION = {
    "aws": "s3:GetObject",
    "azure": "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
}
DECRYPT_ACTION = {
    "aws": "kms:Decrypt",
    "azure": "Microsoft.KeyVault/vaults/keys/unwrap/action",
}
ASSUME_ACTION = "sts:AssumeRole"

CROWN_JEWEL_CLASSES = {"sensitive", "restricted"}


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    reason: str


def is_crown_jewel(r: Resource) -> bool:
    return (r.tags.get("data-classification") in CROWN_JEWEL_CLASSES
            or r.tags.get("crown-jewel", "").lower() == "true")


def _open_ports(inv: Inventory, instance: Resource) -> list[str]:
    ports = []
    for pid in instance.attrs.get("network_policies", []):
        pol = inv.get(pid)
        if not pol:
            continue
        for ing in pol.attrs.get("ingress", []):
            if any(is_open_cidr(c) for c in ing.get("cidrs", [])):
                f, t = ing.get("from_port", -1), ing.get("to_port", -1)
                ports.append("all" if f == -1 else (str(f) if f == t else f"{f}-{t}"))
    return ports


def _role_trusts(target: Resource, source: Resource) -> bool:
    trusted = target.attrs.get("trusted_principals", [])
    src_arn = source.attrs.get("arn", source.id)
    acct_root = f"arn:aws:iam::{source.account}:root" if source.account else None
    return "*" in trusted or src_arn in trusted or (acct_root is not None and acct_root in trusted)


def build_graph(inv: Inventory) -> dict[str, list[Edge]]:
    g: dict[str, list[Edge]] = {INTERNET: []}

    def add(e: Edge) -> None:
        g.setdefault(e.src, []).append(e)

    roles = inv.of_type(ResourceType.IDENTITY_ROLE)
    buckets = [b for b in inv.of_type(ResourceType.STORAGE_BUCKET) if is_crown_jewel(b)]

    for inst in inv.of_type(ResourceType.COMPUTE_INSTANCE):
        if inst.attrs.get("public_ip"):
            ports = _open_ports(inv, inst)
            if ports:
                add(Edge(INTERNET, inst.id, f"public IP {inst.attrs['public_ip']}, open ports {ports}"))
        if inst.attrs.get("role"):
            add(Edge(inst.id, inst.attrs["role"], "instance credentials (IMDS)"))

    for src in roles:
        stmts = src.attrs.get("statements", [])
        for dst in roles:
            if dst.id == src.id or dst.provider != src.provider:
                continue
            if policy_allows(stmts, ASSUME_ACTION, dst.attrs.get("arn", dst.id)) and _role_trusts(dst, src):
                add(Edge(src.id, dst.id, "sts:AssumeRole"))
        for b in buckets:
            if b.provider != src.provider:
                continue
            arn = b.attrs.get("arn", b.id)
            if policy_allows(stmts, READ_ACTION[b.provider], f"{arn}/*"):
                key_id = b.attrs.get("kms_key")
                key = inv.get(key_id) if key_id else None
                if key is not None:
                    # Customer-managed key: the role also needs decrypt on that key.
                    if not policy_allows(stmts, DECRYPT_ACTION[b.provider], key.attrs.get("arn", key.id)):
                        continue
                    add(Edge(src.id, b.id, f"read objects + decrypt with {key.name}"))
                else:
                    add(Edge(src.id, b.id, "read objects"))
    return g


def shortest_paths(g: dict[str, list[Edge]], targets: set[str]) -> dict[str, list[Edge]]:
    prev: dict[str, Edge] = {}
    seen = {INTERNET}
    q = deque([INTERNET])
    while q:
        node = q.popleft()
        for e in g.get(node, []):
            if e.dst in seen:
                continue
            seen.add(e.dst)
            prev[e.dst] = e
            q.append(e.dst)
    out: dict[str, list[Edge]] = {}
    for t in targets & seen:
        hops, cur = [], t
        while cur != INTERNET:
            e = prev[cur]
            hops.append(e)
            cur = e.src
        out[t] = list(reversed(hops))
    return out


def find_attack_paths(inv: Inventory) -> list[Finding]:
    g = build_graph(inv)
    jewels = {b.id for b in inv.of_type(ResourceType.STORAGE_BUCKET) if is_crown_jewel(b)}
    findings = []
    for target, hops in sorted(shortest_paths(g, jewels).items()):
        tgt = inv.get(target)
        path = [INTERNET] + [h.dst for h in hops]
        narrative = " -> ".join(
            [INTERNET] + [f"[{h.reason}] {inv.get(h.dst).name}" for h in hops])
        findings.append(Finding(
            rule_id="CG100",
            title="Internet-reachable path to crown-jewel data",
            severity=Severity.CRITICAL,
            resource_id=target,
            provider=tgt.provider,
            detail=f"{len(hops)}-hop path: {narrative}",
            remediation="Break the chain at the cheapest hop: remove the public ingress, require "
                        "IMDSv2, scope the instance role, or tighten the bucket/key policy to "
                        "named principals with VPC-endpoint conditions.",
            evidence={"hops": [h.__dict__ for h in hops]},
            path=path,
        ))
    return findings

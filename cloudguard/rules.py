"""Posture rules. Each rule is a pure function over one normalized resource.

Add a rule by decorating a generator with @rule. The registry gives the CLI
`--list-rules`, lets suppressions validate rule IDs, and lets tests assert
that every rule has a positive and a negative fixture.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Iterator

from .model import Finding, Inventory, Resource, ResourceType, Severity
from .policy import ADMIN_PORTS, is_admin_statement, is_open_cidr, port_range_covers

RuleFn = Callable[[Resource, Inventory], Iterable[Finding]]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    applies_to: tuple[ResourceType, ...]
    remediation: str
    fn: RuleFn


REGISTRY: dict[str, Rule] = {}


def rule(rule_id: str, title: str, severity: Severity,
         applies_to: tuple[ResourceType, ...], remediation: str):
    def wrap(fn: RuleFn) -> RuleFn:
        if rule_id in REGISTRY:
            raise RuntimeError(f"duplicate rule id {rule_id}")
        REGISTRY[rule_id] = Rule(rule_id, title, severity, applies_to, remediation, fn)
        return fn
    return wrap


def _finding(r: Rule, res: Resource, detail: str, **evidence) -> Finding:
    return Finding(rule_id=r.id, title=r.title, severity=r.severity,
                   resource_id=res.id, provider=res.provider, detail=detail,
                   remediation=r.remediation, evidence=evidence)


# --------------------------------------------------------------------------- storage

@rule("CG001", "Storage bucket is publicly accessible", Severity.HIGH,
      (ResourceType.STORAGE_BUCKET,),
      "Enable account-level public access block (S3 BPA / Azure allowBlobPublicAccess=false) "
      "and serve public content through a CDN with an origin access identity.")
def public_bucket(res: Resource, inv: Inventory) -> Iterator[Finding]:
    if res.attrs.get("public_access") and not res.attrs.get("public_access_blocked", False):
        sev_note = ""
        if res.tags.get("data-classification") in ("sensitive", "restricted"):
            sev_note = " Bucket is tagged as sensitive."
        yield _finding(REGISTRY["CG001"], res, f"{res.name} allows anonymous reads.{sev_note}",
                       public_access=True, classification=res.tags.get("data-classification"))


@rule("CG002", "Storage bucket lacks customer-managed encryption", Severity.MEDIUM,
      (ResourceType.STORAGE_BUCKET,),
      "Encrypt with a customer-managed key (SSE-KMS / Azure CMK) so access to data "
      "also requires key-policy authorization and is logged in the key's audit trail.")
def bucket_encryption(res: Resource, inv: Inventory) -> Iterator[Finding]:
    enc = res.attrs.get("encryption")
    sensitive = res.tags.get("data-classification") in ("sensitive", "restricted")
    if not enc:
        yield _finding(REGISTRY["CG002"], res, f"{res.name} has no server-side encryption configured.",
                       encryption=None)
    elif sensitive and enc in ("AES256", "provider-managed"):
        yield _finding(REGISTRY["CG002"], res,
                       f"{res.name} is sensitive but uses provider-managed keys ({enc}).",
                       encryption=enc)


@rule("CG003", "Azure storage account allows weak transport or shared-key auth", Severity.MEDIUM,
      (ResourceType.STORAGE_BUCKET,),
      "Set minimumTlsVersion=TLS1_2 and allowSharedKeyAccess=false; use Entra ID auth.")
def azure_storage_auth(res: Resource, inv: Inventory) -> Iterator[Finding]:
    if res.provider != "azure":
        return
    problems = []
    if res.attrs.get("min_tls", "TLS1_2") in ("TLS1_0", "TLS1_1"):
        problems.append(f"minimum TLS is {res.attrs['min_tls']}")
    if res.attrs.get("shared_key_access", False):
        problems.append("shared-key (account key) auth is enabled")
    if problems:
        yield _finding(REGISTRY["CG003"], res, f"{res.name}: " + "; ".join(problems), problems=problems)


# --------------------------------------------------------------------------- network

@rule("CG010", "Administrative port exposed to the internet", Severity.HIGH,
      (ResourceType.NETWORK_POLICY,),
      "Remove internet ingress on management ports; reach hosts through an identity-aware "
      "proxy or bastion with short-lived certificates.")
def admin_port_exposed(res: Resource, inv: Inventory) -> Iterator[Finding]:
    for i, ing in enumerate(res.attrs.get("ingress", [])):
        open_cidrs = [c for c in ing.get("cidrs", []) if is_open_cidr(c)]
        if not open_cidrs:
            continue
        exposed = [f"{p}/{name}" for p, name in ADMIN_PORTS.items()
                   if port_range_covers(ing.get("from_port", -1), ing.get("to_port", -1), p)]
        if exposed:
            yield _finding(REGISTRY["CG010"], res,
                           f"{res.name} rule #{i} opens {', '.join(exposed)} to {', '.join(open_cidrs)}",
                           rule_index=i, ports=exposed, cidrs=open_cidrs)


@rule("CG011", "Network policy allows all traffic from the internet", Severity.CRITICAL,
      (ResourceType.NETWORK_POLICY,),
      "Replace any-port internet ingress with explicit ports behind a load balancer.")
def all_traffic_open(res: Resource, inv: Inventory) -> Iterator[Finding]:
    for i, ing in enumerate(res.attrs.get("ingress", [])):
        if ing.get("protocol") in ("-1", "*", "all") and any(is_open_cidr(c) for c in ing.get("cidrs", [])):
            yield _finding(REGISTRY["CG011"], res, f"{res.name} rule #{i} allows all protocols from anywhere",
                           rule_index=i)


# --------------------------------------------------------------------------- compute

@rule("CG020", "Instance metadata service allows IMDSv1", Severity.MEDIUM,
      (ResourceType.COMPUTE_INSTANCE,),
      "Require IMDSv2 (HttpTokens=required) and set hop limit to 1 so SSRF cannot steal "
      "instance-role credentials.")
def imdsv1(res: Resource, inv: Inventory) -> Iterator[Finding]:
    if res.provider == "aws" and not res.attrs.get("imds_v2_required", False):
        yield _finding(REGISTRY["CG020"], res, f"{res.name} accepts unauthenticated IMDSv1 requests")


# --------------------------------------------------------------------------- identity

@rule("CG030", "Identity grants full administrative access", Severity.HIGH,
      (ResourceType.IDENTITY_ROLE,),
      "Replace '*:*' with scoped actions generated from access-analyzer/activity logs; "
      "gate break-glass admin behind just-in-time elevation.")
def admin_role(res: Resource, inv: Inventory) -> Iterator[Finding]:
    for i, s in enumerate(res.attrs.get("statements", [])):
        if is_admin_statement(s):
            yield _finding(REGISTRY["CG030"], res, f"{res.name} statement #{i} allows * on *",
                           statement_index=i)


@rule("CG031", "Role trust policy allows any principal", Severity.CRITICAL,
      (ResourceType.IDENTITY_ROLE,),
      "Restrict the trust policy Principal to specific accounts/services and add an "
      "sts:ExternalId or aws:PrincipalOrgID condition.")
def open_trust(res: Resource, inv: Inventory) -> Iterator[Finding]:
    for p in res.attrs.get("trusted_principals", []):
        if p in ("*", "arn:aws:iam::*:root") and not res.attrs.get("trust_has_condition"):
            yield _finding(REGISTRY["CG031"], res, f"{res.name} can be assumed by principal {p!r}",
                           principal=p)


# --------------------------------------------------------------------------- kubernetes

@rule("CG040", "Kubernetes API endpoint is public without an allowlist", Severity.HIGH,
      (ResourceType.KUBE_CLUSTER,),
      "Make the API endpoint private, or restrict publicAccessCidrs / authorizedIPRanges "
      "to corporate egress ranges.")
def kube_public_api(res: Resource, inv: Inventory) -> Iterator[Finding]:
    if res.attrs.get("endpoint_public"):
        cidrs = res.attrs.get("public_cidrs") or ["0.0.0.0/0"]
        if any(is_open_cidr(c) for c in cidrs):
            yield _finding(REGISTRY["CG040"], res, f"{res.name} API server reachable from {cidrs}",
                           cidrs=cidrs)


@rule("CG041", "Kubernetes secrets are not envelope-encrypted", Severity.MEDIUM,
      (ResourceType.KUBE_CLUSTER,),
      "Enable KMS envelope encryption for Secrets (EKS encryptionConfig / AKS KMS etcd encryption).")
def kube_secret_encryption(res: Resource, inv: Inventory) -> Iterator[Finding]:
    if not res.attrs.get("secrets_encryption"):
        yield _finding(REGISTRY["CG041"], res, f"{res.name} stores Secrets in etcd without a KMS key")


@rule("CG042", "Kubernetes control-plane audit logging disabled", Severity.MEDIUM,
      (ResourceType.KUBE_CLUSTER,),
      "Enable 'audit' control-plane log type and ship it to the SIEM.")
def kube_audit(res: Resource, inv: Inventory) -> Iterator[Finding]:
    if res.attrs.get("audit_logging") is False:  # None = unknown to this collector
        yield _finding(REGISTRY["CG042"], res, f"{res.name} does not emit API audit logs")


# --------------------------------------------------------------------------- crypto / hygiene

@rule("CG050", "Customer-managed key rotation disabled", Severity.LOW,
      (ResourceType.CRYPTO_KEY,),
      "Enable automatic annual rotation (or a rotation policy in Key Vault).")
def key_rotation(res: Resource, inv: Inventory) -> Iterator[Finding]:
    if res.attrs.get("managed_by", "customer") == "customer" and not res.attrs.get("rotation_enabled"):
        yield _finding(REGISTRY["CG050"], res, f"{res.name} has never-rotating key material")


@rule("CG090", "Resource has no owner tag", Severity.INFO,
      tuple(ResourceType),
      "Tag every resource with 'owner' so findings route to a team automatically.")
def owner_tag(res: Resource, inv: Inventory) -> Iterator[Finding]:
    if not res.tags.get("owner"):
        yield _finding(REGISTRY["CG090"], res, f"{res.name} has no 'owner' tag; findings cannot be routed")


def run_rules(inv: Inventory, only: set[str] | None = None) -> list[Finding]:
    out: list[Finding] = []
    for res in inv:
        for r in REGISTRY.values():
            if only and r.id not in only:
                continue
            if res.type in r.applies_to:
                out.extend(r.fn(res, inv))
    return out

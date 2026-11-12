"""Cloud-agnostic resource and finding model.

Every collector (AWS, Azure, offline snapshot) normalizes provider-specific
API output into `Resource` objects. Rules only ever see this model, which is
what makes the rule set cloud-agnostic: a "public storage bucket" check is
written once and applies to S3 buckets and Azure blob containers alike.
"""
from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity {value!r}") from exc


class ResourceType(str, enum.Enum):
    STORAGE_BUCKET = "storage_bucket"
    NETWORK_POLICY = "network_policy"      # AWS security group / Azure NSG
    COMPUTE_INSTANCE = "compute_instance"  # EC2 / Azure VM
    IDENTITY_ROLE = "identity_role"        # IAM role / Azure managed identity
    KUBE_CLUSTER = "kube_cluster"          # EKS / AKS
    CRYPTO_KEY = "crypto_key"              # KMS / Key Vault key


@dataclass
class Resource:
    id: str
    provider: str                 # "aws" | "azure"
    type: ResourceType
    name: str
    region: str = "global"
    account: str = ""
    tags: dict[str, str] = field(default_factory=dict)
    attrs: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Resource":
        return cls(
            id=d["id"],
            provider=d["provider"],
            type=ResourceType(d["type"]),
            name=d.get("name", d["id"]),
            region=d.get("region", "global"),
            account=d.get("account", ""),
            tags=dict(d.get("tags", {})),
            attrs=dict(d.get("attrs", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "provider": self.provider, "type": self.type.value,
            "name": self.name, "region": self.region, "account": self.account,
            "tags": self.tags, "attrs": self.attrs,
        }


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    resource_id: str
    provider: str
    detail: str
    remediation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    path: list[str] = field(default_factory=list)  # attack-path hops, if any
    suppressed_by: str | None = None

    @property
    def fingerprint(self) -> str:
        """Stable ID so findings can be tracked across runs and deduplicated
        in a ticketing system without depending on free-text detail."""
        raw = f"{self.rule_id}|{self.resource_id}|{'>'.join(self.path)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint, "rule_id": self.rule_id,
            "title": self.title, "severity": self.severity.name,
            "resource_id": self.resource_id, "provider": self.provider,
            "detail": self.detail, "remediation": self.remediation,
            "evidence": self.evidence, "path": self.path,
            "suppressed_by": self.suppressed_by,
        }


class Inventory:
    """Indexed collection of resources across every provider and account."""

    def __init__(self, resources: list[Resource] | None = None):
        self._by_id: dict[str, Resource] = {}
        for r in resources or []:
            self.add(r)

    def add(self, r: Resource) -> None:
        if r.id in self._by_id:
            raise ValueError(f"duplicate resource id {r.id}")
        self._by_id[r.id] = r

    def get(self, rid: str) -> Resource | None:
        return self._by_id.get(rid)

    def of_type(self, t: ResourceType) -> list[Resource]:
        return [r for r in self._by_id.values() if r.type == t]

    def __iter__(self):
        return iter(self._by_id.values())

    def __len__(self) -> int:
        return len(self._by_id)

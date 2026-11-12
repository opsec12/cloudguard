"""Live AWS collector (boto3). Read-only: needs only the SecurityAudit managed policy.

Each `_collect_*` method maps one service's API into the normalized model.
Errors on a single service are recorded rather than aborting the whole scan,
because partial visibility is better than none during an incident.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Iterator
from urllib.parse import unquote

from ..model import Resource, ResourceType

log = logging.getLogger(__name__)


class AWSCollector:
    def __init__(self, regions: list[str] | None = None, profile: str | None = None):
        try:
            import boto3  # noqa: WPS433 - optional dependency
        except ImportError as exc:  # pragma: no cover
            raise SystemExit("pip install boto3 to use the live AWS collector") from exc
        self.session = boto3.Session(profile_name=profile)
        self.account = self.session.client("sts").get_caller_identity()["Account"]
        self.regions = regions or [self.session.region_name or "us-east-1"]
        self.errors: list[str] = []

    def collect(self) -> Iterator[Resource]:
        for fn in (self._collect_iam, self._collect_s3):
            yield from self._safe(fn)
        for region in self.regions:
            for fn in (self._collect_ec2, self._collect_eks, self._collect_kms):
                yield from self._safe(fn, region)

    def _safe(self, fn, *args) -> Iterator[Resource]:
        try:
            yield from fn(*args)
        except Exception as exc:  # noqa: BLE001
            msg = f"{fn.__name__}{args}: {exc}"
            log.warning("collector error %s", msg)
            self.errors.append(msg)

    # ------------------------------------------------------------------ IAM
    def _collect_iam(self) -> Iterator[Resource]:
        iam = self.session.client("iam")
        for page in iam.get_paginator("list_roles").paginate():
            for role in page["Roles"]:
                name = role["RoleName"]
                trust = role.get("AssumeRolePolicyDocument") or {}
                if isinstance(trust, str):
                    trust = json.loads(unquote(trust))
                principals, has_cond = [], False
                for s in trust.get("Statement", []):
                    has_cond = has_cond or "Condition" in s
                    p = s.get("Principal", {})
                    if p == "*":
                        principals.append("*")
                    elif isinstance(p, dict):
                        for v in p.values():
                            principals.extend([v] if isinstance(v, str) else v)
                statements = self._role_statements(iam, name)
                tags = {t["Key"]: t["Value"] for t in iam.list_role_tags(RoleName=name).get("Tags", [])}
                yield Resource(id=role["Arn"], provider="aws", type=ResourceType.IDENTITY_ROLE,
                               name=name, account=self.account, tags=tags,
                               attrs={"arn": role["Arn"], "statements": statements,
                                      "trusted_principals": principals,
                                      "trust_has_condition": has_cond})

    def _role_statements(self, iam, role_name: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for pname in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            doc = iam.get_role_policy(RoleName=role_name, PolicyName=pname)["PolicyDocument"]
            out.extend(_statements(doc))
        for att in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
            pol = iam.get_policy(PolicyArn=att["PolicyArn"])["Policy"]
            ver = iam.get_policy_version(PolicyArn=att["PolicyArn"],
                                         VersionId=pol["DefaultVersionId"])["PolicyVersion"]
            out.extend(_statements(ver["Document"]))
        return out

    # ------------------------------------------------------------------ S3
    def _collect_s3(self) -> Iterator[Resource]:
        s3 = self.session.client("s3")
        for b in s3.list_buckets()["Buckets"]:
            name = b["Name"]
            attrs: dict[str, Any] = {"arn": f"arn:aws:s3:::{name}"}
            try:
                cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                attrs["public_access_blocked"] = all(cfg.values())
            except s3.exceptions.ClientError:
                attrs["public_access_blocked"] = False
            try:
                attrs["public_access"] = s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"]
            except s3.exceptions.ClientError:
                attrs["public_access"] = False
            try:
                rule = s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"][0]
                d = rule["ApplyServerSideEncryptionByDefault"]
                attrs["encryption"] = d["SSEAlgorithm"]
                if d.get("KMSMasterKeyID"):
                    attrs["kms_key"] = d["KMSMasterKeyID"]
            except s3.exceptions.ClientError:
                attrs["encryption"] = None
            try:
                tags = {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=name)["TagSet"]}
            except s3.exceptions.ClientError:
                tags = {}
            yield Resource(id=attrs["arn"], provider="aws", type=ResourceType.STORAGE_BUCKET,
                           name=name, account=self.account, tags=tags, attrs=attrs)

    # ------------------------------------------------------------------ EC2
    def _collect_ec2(self, region: str) -> Iterator[Resource]:
        ec2 = self.session.client("ec2", region_name=region)
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for sg in page["SecurityGroups"]:
                ingress = []
                for p in sg.get("IpPermissions", []):
                    cidrs = [r["CidrIp"] for r in p.get("IpRanges", [])] + \
                            [r["CidrIpv6"] for r in p.get("Ipv6Ranges", [])]
                    ingress.append({"protocol": p.get("IpProtocol"), "from_port": p.get("FromPort", -1),
                                    "to_port": p.get("ToPort", -1), "cidrs": cidrs})
                yield Resource(id=sg["GroupId"], provider="aws", type=ResourceType.NETWORK_POLICY,
                               name=sg.get("GroupName", sg["GroupId"]), region=region, account=self.account,
                               tags=_tags(sg), attrs={"ingress": ingress})
        profiles = self._instance_profile_roles()
        for page in ec2.get_paginator("describe_instances").paginate():
            for res in page["Reservations"]:
                for i in res["Instances"]:
                    prof = (i.get("IamInstanceProfile") or {}).get("Arn")
                    yield Resource(
                        id=i["InstanceId"], provider="aws", type=ResourceType.COMPUTE_INSTANCE,
                        name=_tags(i).get("Name", i["InstanceId"]), region=region, account=self.account,
                        tags=_tags(i),
                        attrs={"public_ip": i.get("PublicIpAddress"),
                               "network_policies": [g["GroupId"] for g in i.get("SecurityGroups", [])],
                               "role": profiles.get(prof) if prof else None,
                               "imds_v2_required": i.get("MetadataOptions", {}).get("HttpTokens") == "required"})

    def _instance_profile_roles(self) -> dict[str, str]:
        iam = self.session.client("iam")
        out = {}
        for page in iam.get_paginator("list_instance_profiles").paginate():
            for p in page["InstanceProfiles"]:
                if p["Roles"]:
                    out[p["Arn"]] = p["Roles"][0]["Arn"]
        return out

    # ------------------------------------------------------------------ EKS / KMS
    def _collect_eks(self, region: str) -> Iterator[Resource]:
        eks = self.session.client("eks", region_name=region)
        for name in eks.list_clusters()["clusters"]:
            c = eks.describe_cluster(name=name)["cluster"]
            vpc = c.get("resourcesVpcConfig", {})
            logs = {t for lc in c.get("logging", {}).get("clusterLogging", []) if lc.get("enabled")
                    for t in lc.get("types", [])}
            yield Resource(id=c["arn"], provider="aws", type=ResourceType.KUBE_CLUSTER, name=name,
                           region=region, account=self.account, tags=c.get("tags", {}),
                           attrs={"endpoint_public": vpc.get("endpointPublicAccess", True),
                                  "public_cidrs": vpc.get("publicAccessCidrs", []),
                                  "secrets_encryption": bool(c.get("encryptionConfig")),
                                  "audit_logging": "audit" in logs})

    def _collect_kms(self, region: str) -> Iterator[Resource]:
        kms = self.session.client("kms", region_name=region)
        for page in kms.get_paginator("list_keys").paginate():
            for k in page["Keys"]:
                meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                if meta["KeyManager"] != "CUSTOMER" or meta["KeyState"] != "Enabled":
                    continue
                rot = kms.get_key_rotation_status(KeyId=k["KeyId"])["KeyRotationEnabled"]
                yield Resource(id=meta["Arn"], provider="aws", type=ResourceType.CRYPTO_KEY,
                               name=meta.get("Description") or k["KeyId"], region=region,
                               account=self.account,
                               attrs={"arn": meta["Arn"], "managed_by": "customer", "rotation_enabled": rot})


def _tags(obj: dict) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in obj.get("Tags", [])}


def _statements(doc: Any) -> list[dict[str, Any]]:
    if isinstance(doc, str):
        doc = json.loads(unquote(doc))
    st = doc.get("Statement", [])
    return [st] if isinstance(st, dict) else list(st)

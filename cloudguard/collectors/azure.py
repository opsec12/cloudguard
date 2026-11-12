"""Live Azure collector (azure-identity + azure-mgmt-*). Needs the Reader role.

Azure RBAC role assignments are translated into IAM-style statements so the
same attack-path engine can reason about them:

    {"Effect": "Allow", "Action": [<dataActions>], "Resource": ["<scope>*"]}
"""
from __future__ import annotations

import logging
from typing import Iterator

from ..model import Resource, ResourceType

log = logging.getLogger(__name__)


class AzureCollector:
    def __init__(self, subscription_id: str):
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.authorization import AuthorizationManagementClient
            from azure.mgmt.compute import ComputeManagementClient
            from azure.mgmt.containerservice import ContainerServiceClient
            from azure.mgmt.network import NetworkManagementClient
            from azure.mgmt.storage import StorageManagementClient
        except ImportError as exc:  # pragma: no cover
            raise SystemExit("pip install azure-identity azure-mgmt-authorization azure-mgmt-compute "
                             "azure-mgmt-containerservice azure-mgmt-network azure-mgmt-storage") from exc
        cred = DefaultAzureCredential()
        self.sub = subscription_id
        self.auth = AuthorizationManagementClient(cred, subscription_id)
        self.compute = ComputeManagementClient(cred, subscription_id)
        self.aks = ContainerServiceClient(cred, subscription_id)
        self.network = NetworkManagementClient(cred, subscription_id)
        self.storage = StorageManagementClient(cred, subscription_id)
        self.errors: list[str] = []

    def collect(self) -> Iterator[Resource]:
        for fn in (self._storage, self._nsgs, self._vms, self._aks):
            try:
                yield from fn()
            except Exception as exc:  # noqa: BLE001
                self.errors.append(f"{fn.__name__}: {exc}")
                log.warning("azure collector error in %s: %s", fn.__name__, exc)

    def _storage(self) -> Iterator[Resource]:
        for acct in self.storage.storage_accounts.list():
            enc = acct.encryption
            key_source = getattr(enc, "key_source", None) if enc else None
            yield Resource(
                id=acct.id, provider="azure", type=ResourceType.STORAGE_BUCKET, name=acct.name,
                region=acct.location, account=self.sub, tags=acct.tags or {},
                attrs={"arn": acct.id,
                       "public_access": bool(acct.allow_blob_public_access),
                       "encryption": "customer-managed" if key_source == "Microsoft.Keyvault"
                                     else "provider-managed",
                       "min_tls": acct.minimum_tls_version,
                       "shared_key_access": acct.allow_shared_key_access is not False})

    def _nsgs(self) -> Iterator[Resource]:
        for nsg in self.network.network_security_groups.list_all():
            ingress = []
            for r in nsg.security_rules or []:
                if r.direction != "Inbound" or r.access != "Allow":
                    continue
                srcs = r.source_address_prefixes or [r.source_address_prefix]
                ranges = r.destination_port_ranges or [r.destination_port_range]
                for pr in ranges:
                    lo, _, hi = (pr or "*").partition("-")
                    f = -1 if lo == "*" else int(lo)
                    t = -1 if lo == "*" else int(hi or lo)
                    ingress.append({"protocol": "all" if r.protocol == "*" else r.protocol.lower(),
                                    "from_port": f, "to_port": t, "cidrs": srcs})
            yield Resource(id=nsg.id, provider="azure", type=ResourceType.NETWORK_POLICY, name=nsg.name,
                           region=nsg.location, account=self.sub, tags=nsg.tags or {},
                           attrs={"ingress": ingress})

    def _vms(self) -> Iterator[Resource]:
        nic_index = {n.id.lower(): n for n in self.network.network_interfaces.list_all()}
        assignments = list(self.auth.role_assignments.list_for_subscription())
        for vm in self.compute.virtual_machines.list_all():
            nsgs, public_ip = [], None
            for ref in vm.network_profile.network_interfaces:
                nic = nic_index.get(ref.id.lower())
                if not nic:
                    continue
                if nic.network_security_group:
                    nsgs.append(nic.network_security_group.id)
                for ipc in nic.ip_configurations or []:
                    if ipc.public_ip_address:
                        public_ip = ipc.public_ip_address.id
            role_id = None
            if vm.identity and vm.identity.principal_id:
                role_id = f"{vm.id}/identity"
                yield self._identity(role_id, vm, assignments)
            yield Resource(id=vm.id, provider="azure", type=ResourceType.COMPUTE_INSTANCE, name=vm.name,
                           region=vm.location, account=self.sub, tags=vm.tags or {},
                           attrs={"public_ip": public_ip, "network_policies": nsgs, "role": role_id})

    def _identity(self, rid: str, vm, assignments) -> Resource:
        statements = []
        for a in assignments:
            if a.principal_id != vm.identity.principal_id:
                continue
            definition = self.auth.role_definitions.get_by_id(a.role_definition_id)
            for perm in definition.permissions:
                acts = list(perm.actions or []) + list(perm.data_actions or [])
                statements.append({"Effect": "Allow", "Action": acts, "Resource": [a.scope.rstrip("/") + "*"]})
        return Resource(id=rid, provider="azure", type=ResourceType.IDENTITY_ROLE,
                        name=f"{vm.name}-managed-identity", region=vm.location, account=self.sub,
                        attrs={"arn": rid, "statements": statements, "trusted_principals": [vm.id]})

    def _aks(self) -> Iterator[Resource]:
        for c in self.aks.managed_clusters.list():
            api = c.api_server_access_profile
            private = bool(api and api.enable_private_cluster)
            yield Resource(
                id=c.id, provider="azure", type=ResourceType.KUBE_CLUSTER, name=c.name,
                region=c.location, account=self.sub, tags=c.tags or {},
                attrs={"endpoint_public": not private,
                       "public_cidrs": list(api.authorized_ip_ranges or []) if api else [],
                       "secrets_encryption": bool(c.security_profile and c.security_profile.azure_key_vault_kms
                                                  and c.security_profile.azure_key_vault_kms.enabled),
                       "audit_logging": None})  # lives in diagnostic settings; resolved by a separate check

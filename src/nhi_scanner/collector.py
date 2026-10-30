"""Live collection from Microsoft Graph and Azure Resource Manager.

Required permissions for the scanning identity (application permissions):
  Microsoft Graph: Application.Read.All, Directory.Read.All,
                   RoleManagement.Read.Directory, AuditLog.Read.All
  Azure:           Reader at the root / management-group scope (optional)

Authentication uses ``DefaultAzureCredential``: environment variables
(AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET), workload identity,
managed identity or an ``az login`` session.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, Optional

import requests

from .snapshot import AGENT_ID_UNREADABLE, TenantSnapshot, parse_graph_datetime

GRAPH = "https://graph.microsoft.com"
ARM = "https://management.azure.com"
MS_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

_OWNER_EXPAND = "owners($select=id,userPrincipalName,displayName)"
_APP_SELECT = (
    "id,appId,displayName,createdDateTime,signInAudience,tags,publisherDomain,"
    "passwordCredentials,keyCredentials"
)
_SP_SELECT = (
    "id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,"
    "tags,verifiedPublisher,alternativeNames,preferredSingleSignOnMode,passwordCredentials,keyCredentials"
)


# Entra Agent ID: agent identities are service principals listed through their own type-cast
# endpoint; the plain /servicePrincipals list is not documented to include them.
AGENT_IDENTITIES = "/v1.0/servicePrincipals/microsoft.graph.agentIdentity"
_SPONSOR_SELECT = "id,userPrincipalName,displayName"


class CollectionError(RuntimeError):
    pass


class _Http:
    """Thin authenticated client with paging and back-off on 429/5xx and network errors."""

    def __init__(self, credential: Any, scope: str, base: str, tenant_id: Optional[str] = None):
        self._credential = credential
        self._scope = scope
        self._tenant_id = tenant_id
        self._base = base
        self._token: Optional[Any] = None
        self._session = requests.Session()

    def _auth_header(self) -> dict[str, str]:
        if self._token is None or self._token.expires_on - 120 < time.time():
            kwargs = {"tenant_id": self._tenant_id} if self._tenant_id else {}
            self._token = self._credential.get_token(self._scope, **kwargs)
        return {"Authorization": f"Bearer {self._token.token}"}

    def get(self, url: str, params: Optional[dict[str, str]] = None) -> dict[str, Any]:
        if url.startswith("/"):
            url = self._base + url
        failure = ""
        for attempt in range(6):
            try:
                resp = self._session.get(url, params=params, headers=self._auth_header(), timeout=60)
            except requests.RequestException as exc:  # reset, timeout, DNS: usually transient
                failure = str(exc)
                time.sleep(2**attempt)
                continue
            if resp.status_code in (429, 500, 502, 503, 504):
                failure = f"HTTP {resp.status_code}"
                time.sleep(float(resp.headers.get("Retry-After", 2**attempt)))
                continue
            if resp.status_code >= 400:
                raise CollectionError(f"GET {url} -> {resp.status_code}: {resp.text[:300]}")
            return resp.json()
        raise CollectionError(f"GET {url} kept failing after retries: {failure}")

    def paged(self, url: str, params: Optional[dict[str, str]] = None) -> Iterator[dict[str, Any]]:
        page = self.get(url, params)
        while True:
            yield from page.get("value", [])
            nxt = page.get("@odata.nextLink") or page.get("nextLink")
            if not nxt:
                return
            page = self.get(nxt)


def _merge_agent_identities(graph: _Http, sps: list[dict[str, Any]], warnings: list[str]) -> None:
    """Add Entra Agent ID identities to ``sps`` (or enrich the ones already there), with their sponsors.

    Sponsors are the accountable humans of an agent identity. Each agent gets a ``sponsors`` list; when
    they cannot be read the key is left out, and the agent is then not reported as orphaned.
    """
    try:
        agents = list(graph.paged(AGENT_IDENTITIES, {"$expand": _OWNER_EXPAND}))
    except CollectionError as exc:
        warnings.append(
            f"{AGENT_ID_UNREADABLE} (needs AgentIdentity.Read.All); agents created with "
            f"Agent ID may be missing from this scan. [{exc}]"
        )
        return
    index = {sp["id"]: i for i, sp in enumerate(sps)}
    sponsors_readable = True
    for agent in agents:
        agent.setdefault("@odata.type", "#microsoft.graph.agentIdentity")
        if sponsors_readable:
            try:
                agent["sponsors"] = list(graph.paged(
                    f"/beta/servicePrincipals/{agent['id']}/microsoft.graph.agentIdentity/sponsors",
                    {"$select": _SPONSOR_SELECT},
                ))
            except CollectionError as exc:
                sponsors_readable = False
                warnings.append(
                    "Sponsors of Entra Agent ID identities not readable (Microsoft currently documents "
                    "AgentIdentity.ReadWrite.All for this read); those agents are not reported as orphaned. "
                    f"[{exc}]"
                )
        if agent["id"] in index:
            sps[index[agent["id"]]].update(agent)
        else:
            sps.append(agent)


def collect(
    tenant_id: Optional[str] = None,
    include_azure_rbac: bool = True,
    progress: Callable[[str], None] = lambda _msg: None,
) -> TenantSnapshot:
    try:
        from azure.identity import DefaultAzureCredential
    except ImportError as exc:  # pragma: no cover
        raise CollectionError("azure-identity is required for live scans: pip install -r requirements.txt") from exc

    logging.getLogger("azure.identity").setLevel(logging.CRITICAL)  # failures surface as exceptions the CLI explains
    credential = DefaultAzureCredential(
        process_timeout=60,  # the 10s default can expire on a first token, silently losing Azure RBAC
        **({"additionally_allowed_tenants": ["*"]} if tenant_id else {}),
    )
    graph = _Http(credential, f"{GRAPH}/.default", GRAPH, tenant_id)
    warnings: list[str] = []

    progress("Tenant")
    try:
        org = graph.get("/v1.0/organization", {"$select": "id,displayName"})["value"][0]
    except CollectionError as exc:
        if not tenant_id:
            raise CollectionError(f"Cannot read the tenant; pass --tenant-id to continue without it. [{exc}]") from exc
        org = {"id": tenant_id}
        warnings.append(f"Tenant details not read; the tenant ID is used as its name. [{exc}]")

    # Every check starts from these two lists, so without them there is nothing to report
    try:
        progress("App registrations")
        apps = list(graph.paged("/v1.0/applications", {"$select": _APP_SELECT, "$expand": _OWNER_EXPAND}))

        progress("Service principals")
        sps = list(graph.paged("/v1.0/servicePrincipals", {"$select": _SP_SELECT, "$expand": _OWNER_EXPAND}))
    except CollectionError as exc:
        raise CollectionError(
            f"Cannot read app registrations and service principals (needs Application.Read.All). [{exc}]"
        ) from exc

    progress("Entra Agent ID identities")
    _merge_agent_identities(graph, sps, warnings)

    progress("Microsoft Graph application permissions")
    msgraph = next((sp for sp in sps if sp.get("appId") == MS_GRAPH_APP_ID), None)
    graph_roles: dict[str, str] = {}
    graph_assignments: Optional[list[dict[str, Any]]] = None
    if msgraph:
        try:
            full = graph.get(f"/v1.0/servicePrincipals/{msgraph['id']}", {"$select": "appRoles"})
            graph_roles = {r["id"]: r["value"] for r in full.get("appRoles", [])}
            graph_assignments = [
                a for a in graph.paged(f"/v1.0/servicePrincipals/{msgraph['id']}/appRoleAssignedTo")
                if a.get("principalType") == "ServicePrincipal"
            ]
        except CollectionError as exc:
            graph_assignments = None
            warnings.append(
                f"Microsoft Graph application permissions not read (needs Application.Read.All); "
                f"permission rules skipped. [{exc}]"
            )
    else:
        warnings.append("Microsoft Graph service principal not found; permission rules skipped.")

    progress("Directory roles")
    role_defs: dict[str, dict[str, Any]] = {}
    role_assignments: Optional[list[dict[str, Any]]] = None
    try:
        role_defs = {
            d["id"]: {"displayName": d["displayName"], "templateId": d.get("templateId")}
            for d in graph.paged("/v1.0/roleManagement/directory/roleDefinitions",
                                 {"$select": "id,displayName,templateId"})
        }
        sp_ids = {sp["id"] for sp in sps}
        role_assignments = [
            a for a in graph.paged("/v1.0/roleManagement/directory/roleAssignments")
            if a.get("principalId") in sp_ids
        ]
    except CollectionError as exc:
        warnings.append(
            f"Entra directory roles not read (needs RoleManagement.Read.Directory); role rule skipped. [{exc}]"
        )

    progress("Service principal sign-in activity")
    signin: Optional[dict[str, Optional[datetime]]]
    try:
        signin = {
            row["appId"]: parse_graph_datetime((row.get("lastSignInActivity") or {}).get("lastSignInDateTime"))
            for row in graph.paged("/beta/reports/servicePrincipalSignInActivities")
        }
    except CollectionError as exc:
        signin = None
        warnings.append(
            "Sign-in activity unavailable (needs AuditLog.Read.All and Entra ID P1); "
            f"dormancy rules skipped. [{exc}]"
        )
    else:
        # Tenants without Entra ID P1 can answer 200 with no rows: that proves nothing, not "never used"
        if not signin:
            signin = None
            warnings.append(
                "Sign-in activity report is empty (it needs Entra ID P1 and recorded activity); dormancy rules skipped."
            )

    azure: Optional[list[dict[str, Any]]] = None
    if include_azure_rbac:
        progress("Azure RBAC role assignments")
        try:
            azure = _collect_azure_rbac(_Http(credential, f"{ARM}/.default", ARM, tenant_id), warnings)
        except Exception as exc:  # noqa: BLE001 — Azure is optional; never fail the Entra scan
            warnings.append(f"Azure RBAC not scanned: {exc}")

    return TenantSnapshot(
        tenant_id=org["id"],
        tenant_name=org.get("displayName") or org["id"],
        collected_at=datetime.now(timezone.utc),
        applications=apps,
        service_principals=sps,
        graph_app_role_assignments=graph_assignments,
        graph_app_roles=graph_roles,
        directory_role_assignments=role_assignments,
        directory_role_definitions=role_defs,
        signin_activity=signin,
        azure_role_assignments=azure,
        warnings=warnings,
    )


def _collect_azure_rbac(arm: _Http, warnings: list[str]) -> list[dict[str, Any]]:
    """Role assignments of every readable subscription; one unreadable subscription only costs a warning."""
    out: dict[str, dict[str, Any]] = {}
    subs = list(arm.paged("/subscriptions", {"api-version": "2022-12-01"}))
    unreadable = 0
    for sub in subs:
        base = f"/subscriptions/{sub['subscriptionId']}/providers/Microsoft.Authorization"
        try:
            role_names = {
                d["name"]: d["properties"]["roleName"]
                for d in arm.paged(f"{base}/roleDefinitions", {"api-version": "2022-04-01"})
            }
            assignments = list(arm.paged(f"{base}/roleAssignments", {"api-version": "2022-04-01"}))
        except CollectionError as exc:
            unreadable += 1
            warnings.append(f"Azure RBAC not read for subscription {sub['subscriptionId']}. [{exc}]")
            continue
        for ra in assignments:
            props = ra["properties"]
            if props.get("principalType") != "ServicePrincipal":
                continue
            def_guid = props["roleDefinitionId"].rsplit("/", 1)[-1]
            # assignments inherited from management groups show up in every subscription
            out[ra["id"]] = {
                "id": ra["id"],
                "principalId": props["principalId"],
                "roleName": role_names.get(def_guid, def_guid),
                "scope": props["scope"],
            }
    if subs and unreadable == len(subs):
        raise CollectionError("no subscription could be read")
    return list(out.values())

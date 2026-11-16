"""Live collection from Microsoft Graph and Azure Resource Manager.

Required permissions for the scanning identity (application permissions):
  Microsoft Graph: Application.Read.All, Directory.Read.All (also covers the
                   delegated permission grants), RoleManagement.Read.Directory,
                   AuditLog.Read.All
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

from .snapshot import (
    AGENT_ID_UNREADABLE,
    SRC_AGENT_IDENTITIES,
    SRC_APPLICATIONS,
    SRC_AZURE_RBAC,
    SRC_DELEGATED_GRANTS,
    SRC_DIRECTORY_ROLES,
    SRC_FEDERATED_APPS,
    SRC_FEDERATED_MI,
    SRC_GRAPH_PERMISSIONS,
    SRC_SERVICE_PRINCIPALS,
    SRC_SIGNIN_ACTIVITY,
    SRC_SPONSORS,
    TenantSnapshot,
    parse_graph_datetime,
)

GRAPH = "https://graph.microsoft.com"
ARM = "https://management.azure.com"
MS_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

_OWNER_EXPAND = "owners($select=id,userPrincipalName,displayName,accountEnabled)"
_APP_SELECT = (
    "id,appId,displayName,createdDateTime,signInAudience,tags,publisherDomain,"
    "passwordCredentials,keyCredentials,description,notes"
)
_SP_SELECT = (
    "id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,"
    "tags,verifiedPublisher,alternativeNames,preferredSingleSignOnMode,passwordCredentials,keyCredentials,"
    "description,notes"
)
# The 0.1 reads, without owner account status, description and notes. Used only if Graph refuses the full ones.
_OWNER_EXPAND_BASIC = "owners($select=id,userPrincipalName,displayName)"
_APP_SELECT_BASIC = _APP_SELECT.removesuffix(",description,notes")
_SP_SELECT_BASIC = _SP_SELECT.removesuffix(",description,notes")


# Entra Agent ID: agent identities are service principals listed through their own type-cast
# endpoint; the plain /servicePrincipals list is not documented to include them.
AGENT_IDENTITIES = "/v1.0/servicePrincipals/microsoft.graph.agentIdentity"
MANAGED_IDENTITY_API = "2024-11-30"
_SPONSOR_SELECT = "id,userPrincipalName,displayName,accountEnabled"


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


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _merge_agent_identities(
    graph: _Http, sps: list[dict[str, Any]], warnings: list[str], read_at: dict[str, datetime],
    owner_expand: str = _OWNER_EXPAND,
) -> None:
    """Add Entra Agent ID identities to ``sps`` (or enrich the ones already there), with their sponsors.

    Sponsors are the accountable humans of an agent identity. Each agent gets a ``sponsors`` list; when
    they cannot be read the key is left out, and the agent is then not reported as orphaned.
    """
    try:
        agents = list(graph.paged(AGENT_IDENTITIES, {"$expand": owner_expand}))
        read_at[SRC_AGENT_IDENTITIES] = _now()
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
                    f"/v1.0/servicePrincipals/{agent['id']}/microsoft.graph.agentIdentity/sponsors",
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
    if agents and sponsors_readable:
        read_at[SRC_SPONSORS] = _now()


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
    read_at: dict[str, datetime] = {}

    progress("Tenant")
    try:
        org = graph.get("/v1.0/organization", {"$select": "id,displayName"})["value"][0]
    except CollectionError as exc:
        if not tenant_id:
            raise CollectionError(f"Cannot read the tenant; pass --tenant-id to continue without it. [{exc}]") from exc
        org = {"id": tenant_id}
        warnings.append(f"Tenant details not read; the tenant ID is used as its name. [{exc}]")

    # Every check starts from these two lists, so without them there is nothing to report
    owner_expand = _OWNER_EXPAND
    try:
        try:
            apps, sps = _read_directory(graph, progress, read_at, _APP_SELECT, _SP_SELECT, _OWNER_EXPAND)
        except CollectionError as exc:
            if " -> 400" not in str(exc):
                raise
            # A Graph that refuses the fuller select must not cost the whole scan: fall back to the 0.1 reads
            owner_expand = _OWNER_EXPAND_BASIC
            warnings.append(
                "Owner account status, descriptions and notes not read (Graph refused the fuller query); "
                f"identity records leave them empty. [{exc}]"
            )
            apps, sps = _read_directory(graph, progress, read_at, _APP_SELECT_BASIC, _SP_SELECT_BASIC, owner_expand)
    except CollectionError as exc:
        raise CollectionError(
            f"Cannot read app registrations and service principals (needs Application.Read.All). [{exc}]"
        ) from exc

    progress("Entra Agent ID identities")
    _merge_agent_identities(graph, sps, warnings, read_at, owner_expand)

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
            read_at[SRC_GRAPH_PERMISSIONS] = _now()
        except CollectionError as exc:
            graph_assignments = None
            warnings.append(
                f"Microsoft Graph application permissions not read (needs Application.Read.All); "
                f"permission rules skipped. [{exc}]"
            )
    else:
        warnings.append("Microsoft Graph service principal not found; permission rules skipped.")

    progress("Federated credentials of app registrations")
    app_fic: Optional[dict[str, list[dict[str, Any]]]] = {}
    try:
        # one read per app: Graph documents no $expand for this relationship, and $batch would be a POST
        for app in apps:
            app_fic[app["id"]] = list(graph.paged(f"/v1.0/applications/{app['id']}/federatedIdentityCredentials"))
        read_at[SRC_FEDERATED_APPS] = _now()
    except CollectionError as exc:
        app_fic = None
        warnings.append(f"Federated credentials of app registrations not read (needs Application.Read.All); "
                        f"the federation rule skips them. [{exc}]")

    progress("Delegated permission grants")
    delegated: Optional[list[dict[str, Any]]] = None
    try:
        delegated = list(graph.paged("/v1.0/oauth2PermissionGrants"))
        read_at[SRC_DELEGATED_GRANTS] = _now()
    except CollectionError as exc:
        warnings.append(
            "Delegated permission grants not read (needs Directory.Read.All or DelegatedPermissionGrant.Read.All); "
            f"consent rules skipped. [{exc}]"
        )

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
        read_at[SRC_DIRECTORY_ROLES] = _now()
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
        read_at[SRC_SIGNIN_ACTIVITY] = _now()
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
    mi_fic: Optional[dict[str, list[dict[str, Any]]]] = None
    if include_azure_rbac:
        progress("Azure RBAC role assignments")
        try:
            azure = _collect_azure_rbac(_Http(credential, f"{ARM}/.default", ARM, tenant_id), warnings)
            read_at[SRC_AZURE_RBAC] = _now()
        except Exception as exc:  # noqa: BLE001 — Azure is optional; never fail the Entra scan
            warnings.append(f"Azure RBAC not scanned: {exc}")
        progress("Federated credentials of user-assigned managed identities")
        try:
            mi_fic = _collect_mi_federation(_Http(credential, f"{ARM}/.default", ARM, tenant_id), warnings)
            read_at[SRC_FEDERATED_MI] = _now()
        except Exception as exc:  # noqa: BLE001 — same as Azure RBAC: optional
            warnings.append(f"Federated credentials of managed identities not read: {exc}")

    return TenantSnapshot(
        tenant_id=org["id"],
        tenant_name=org.get("displayName") or org["id"],
        collected_at=_now(),
        applications=apps,
        service_principals=sps,
        graph_app_role_assignments=graph_assignments,
        graph_app_roles=graph_roles,
        directory_role_assignments=role_assignments,
        directory_role_definitions=role_defs,
        signin_activity=signin,
        azure_role_assignments=azure,
        warnings=warnings,
        read_at=read_at,
        owner_status_read=owner_expand == _OWNER_EXPAND,
        delegated_permission_grants=delegated,
        app_federated_credentials=app_fic,
        mi_federated_credentials=mi_fic,
    )


def _read_directory(
    graph: _Http, progress: Callable[[str], None], read_at: dict[str, datetime],
    app_select: str, sp_select: str, owner_expand: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    progress("App registrations")
    apps = list(graph.paged("/v1.0/applications", {"$select": app_select, "$expand": owner_expand}))
    read_at[SRC_APPLICATIONS] = _now()

    progress("Service principals")
    sps = list(graph.paged("/v1.0/servicePrincipals", {"$select": sp_select, "$expand": owner_expand}))
    read_at[SRC_SERVICE_PRINCIPALS] = _now()
    return apps, sps


def _collect_mi_federation(arm: _Http, warnings: list[str]) -> dict[str, list[dict[str, Any]]]:
    """Federated credentials of every user-assigned managed identity, keyed by its service principal id."""
    out: dict[str, list[dict[str, Any]]] = {}
    subs = list(arm.paged("/subscriptions", {"api-version": "2022-12-01"}))
    unreadable = 0
    for sub in subs:
        try:
            identities = list(arm.paged(
                f"/subscriptions/{sub['subscriptionId']}/providers/Microsoft.ManagedIdentity/userAssignedIdentities",
                {"api-version": MANAGED_IDENTITY_API}))
            for mi in identities:
                principal = (mi.get("properties") or {}).get("principalId")
                if not principal:
                    continue
                out[principal] = [
                    {"id": f.get("id") or f.get("name"), "name": f.get("name"), "identity_id": mi["id"],
                     "issuer": (f.get("properties") or {}).get("issuer"),
                     "subject": (f.get("properties") or {}).get("subject"),
                     "audiences": (f.get("properties") or {}).get("audiences") or []}
                    for f in arm.paged(f"{mi['id']}/federatedIdentityCredentials", {"api-version": MANAGED_IDENTITY_API})
                ]
        except CollectionError as exc:
            unreadable += 1
            warnings.append(f"Managed identity federated credentials not read for subscription {sub['subscriptionId']}. [{exc}]")
    if subs and unreadable == len(subs):
        raise CollectionError("no subscription could be read")
    return out


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

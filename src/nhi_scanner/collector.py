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
import random
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, Optional, TypeVar

import requests
from requests.compat import urlsplit  # the read-only test bans urllib imports: only requests talks to the network

from .snapshot import (
    AGENT_ID_UNREADABLE,
    RESOURCE_APIS,
    SRC_AGENT_IDENTITIES,
    SRC_APPLICATIONS,
    SRC_AZURE_RBAC,
    SRC_DELEGATED_GRANTS,
    SRC_AI_ACCOUNTS,
    SRC_DIRECTORY_ROLES,
    SRC_FEDERATED_APPS,
    SRC_FEDERATED_MI,
    SRC_GRAPH_PERMISSIONS,
    SRC_RESOURCE_PERMISSIONS,
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
COGNITIVE_SERVICES_API = "2024-10-01"
AI_KINDS = {"OpenAI", "AIServices"}
_SPONSOR_SELECT = "id,userPrincipalName,displayName,accountEnabled"

# Scale (T-14). Graph's $batch would group reads into one request, but it is a POST, and this scanner sends only GET.
# A large tenant is read instead with the biggest page Graph allows, with relationships expanded inside the list
# where Graph documents it, and with the few per-object reads left done a handful at a time.
PAGE_SIZE = "999"
PARALLEL_READS = 8

MAX_ERRORS = 6
# Throttled requests are retried for up to ten minutes of waiting each, never sooner than MIN_THROTTLED_WAIT; the
# count only bounds a server that keeps answering 429 with almost no wait.
MAX_THROTTLED = 1000
MIN_THROTTLED_WAIT = 0.05
MAX_THROTTLED_WAIT = 600.0
MAX_RETRY_AFTER = 120.0

_T = TypeVar("_T")
_R = TypeVar("_R")


MAX_PAGES = 50_000  # 5 million objects at Graph's smallest page: past it, a server is paging forever
_OBJECT_ID = re.compile(r"^[0-9A-Za-z-]{1,64}$")
_MI_RESOURCE = re.compile(r"^/subscriptions/[0-9A-Za-z-]{1,64}/resourceGroups/[^/?#%\\]{1,90}/providers/"
                          r"Microsoft\.ManagedIdentity/userAssignedIdentities/[^/?#%\\]{1,128}$", re.IGNORECASE)


def _seg(value: Any) -> str:
    """An object id from a response, checked before it becomes part of a URL path: no '/', '?', '#' or '..'."""
    if isinstance(value, str) and _OBJECT_ID.match(value):
        return value
    raise CollectionError(f"refusing an object id that is not a plain identifier: {str(value)[:80]!r}")


def _mi_path(value: Any) -> str:
    if isinstance(value, str) and _MI_RESOURCE.match(value) and "/../" not in value + "/":
        return value
    raise CollectionError(f"refusing a managed identity resource id of unexpected shape: {str(value)[:120]!r}")


def _retry_after(headers: Any, default: float) -> float:
    """Seconds to wait, from Retry-After when it is a sane number of seconds; never forever, never negative."""
    try:
        value = float(headers.get("Retry-After", default))
    except (TypeError, ValueError):  # an HTTP date or garbage: wait the default
        return float(default)
    return min(value, MAX_RETRY_AFTER) if value >= 0 else float(default)  # NaN fails the comparison too


def _parallel(fn: Callable[[_T], _R], items: list[_T]) -> list[_R]:
    """``fn`` over ``items``, in order, a few at a time. The first failure stops the reads not yet started."""
    pool = ThreadPoolExecutor(max_workers=PARALLEL_READS)
    try:
        return list(pool.map(fn, items))
    finally:
        pool.shutdown(wait=True, cancel_futures=True)


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
        self._token_lock = threading.Lock()
        self._local = threading.local()  # one connection pool per thread: a requests.Session is not thread-safe

    @property
    def _session(self) -> requests.Session:
        if not hasattr(self._local, "session"):
            self._local.session = requests.Session()
        return self._local.session

    @_session.setter
    def _session(self, session: requests.Session) -> None:
        self._local.session = session

    def _auth_header(self) -> dict[str, str]:
        with self._token_lock:
            if self._token is None or self._token.expires_on - 120 < time.time():
                kwargs = {"tenant_id": self._tenant_id} if self._tenant_id else {}
                self._token = self._credential.get_token(self._scope, **kwargs)
            return {"Authorization": f"Bearer {self._token.token}"}

    def _resolve(self, url: str) -> str:
        """Absolute URL on this API's host. Paging links and ids come from responses: never send the token elsewhere."""
        if url.startswith("/") and not url.startswith("//"):
            url = self._base + url
        target, base = urlsplit(url), urlsplit(self._base)
        if (target.scheme, target.hostname, target.port) != (base.scheme, base.hostname, base.port) or target.username or target.password:
            raise CollectionError(f"refusing to send the token to host {target.hostname or url!r}: only {base.hostname} is allowed")
        if any(seg in (".", "..") for seg in target.path.split("/")) or "%2e" in target.path.lower():
            raise CollectionError(f"refusing a path with dot segments: {target.path[:120]!r}")
        return url

    def get(self, url: str, params: Optional[dict[str, str]] = None) -> dict[str, Any]:
        url = self._resolve(url)
        failure = ""
        errors = throttled = 0
        waited = 0.0
        # Throttling is Graph asking to wait, not a failure: a large tenant read a few requests at a time meets it
        # often, so it has its own, larger budget. Errors and outages keep the short one.
        while errors < MAX_ERRORS and throttled < MAX_THROTTLED and waited < MAX_THROTTLED_WAIT:
            try:
                # redirects are not followed: data comes only from the API host, and the token stays there
                resp = self._session.get(url, params=params, headers=self._auth_header(), timeout=60,
                                         allow_redirects=False)
            except requests.RequestException as exc:  # reset, timeout, DNS: usually transient
                failure = str(exc)
                time.sleep(2**errors)
                errors += 1
                continue
            if resp.status_code == 429:
                failure = "HTTP 429 (throttled)"
                # a little jitter, so that parallel reads told to wait the same time do not all come back at once
                delay = max(_retry_after(resp.headers, 2 ** min(throttled, 5)), MIN_THROTTLED_WAIT)
                delay *= 1 + random.random() / 4
                time.sleep(delay)
                waited += delay
                throttled += 1
                continue
            if resp.status_code in (500, 502, 503, 504):
                failure = f"HTTP {resp.status_code}"
                time.sleep(_retry_after(resp.headers, 2**errors))
                errors += 1
                continue
            if resp.status_code >= 300:
                raise CollectionError(f"GET {url} -> {resp.status_code}: {resp.text[:300]}")
            try:
                body = resp.json()
            except ValueError as exc:  # an HTML page from a proxy, a truncated body
                raise CollectionError(f"GET {url} -> {resp.status_code}: the response is not JSON") from exc
            if not isinstance(body, dict):
                raise CollectionError(f"GET {url} -> {resp.status_code}: the response is not a JSON object")
            return body
        raise CollectionError(f"GET {url} kept failing after retries: {failure}")

    def paged(self, url: str, params: Optional[dict[str, str]] = None) -> Iterator[dict[str, Any]]:
        page = self.get(url, params)
        yield from self._pages(page)

    def paged_large(self, url: str, params: Optional[dict[str, str]] = None) -> Iterator[dict[str, Any]]:
        """Like ``paged``, with pages of 999 objects instead of Graph's default 100; without $top if it is refused."""
        try:
            page = self.get(url, {**(params or {}), "$top": PAGE_SIZE})
        except CollectionError as exc:
            if " -> 400" not in str(exc):
                raise
            page = self.get(url, params)
        yield from self._pages(page)

    def _pages(self, page: dict[str, Any]) -> Iterator[dict[str, Any]]:
        seen: set[str] = set()
        while True:
            rows = page.get("value", [])
            if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
                raise CollectionError("a page of results is not a list of objects")
            yield from rows
            nxt = page.get("@odata.nextLink") or page.get("nextLink")
            if not nxt:
                return
            if not isinstance(nxt, str) or nxt in seen or len(seen) >= MAX_PAGES:
                raise CollectionError("paging does not end: a next link repeats or the pages never stop")
            seen.add(nxt)
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
        agents = list(graph.paged_large(AGENT_IDENTITIES, {"$expand": owner_expand}))
        read_at[SRC_AGENT_IDENTITIES] = _now()
    except CollectionError as exc:
        warnings.append(
            f"{AGENT_ID_UNREADABLE} (needs AgentIdentity.Read.All); agents created with "
            f"Agent ID may be missing from this scan. [{exc}]"
        )
        return
    index = {sp["id"]: i for i, sp in enumerate(sps)}

    def sponsors(agent: dict[str, Any]) -> list[dict[str, Any]]:
        path = f"/v1.0/servicePrincipals/{_seg(agent.get('id'))}/microsoft.graph.agentIdentity/sponsors"
        return list(graph.paged(path, {"$select": _SPONSOR_SELECT}))

    sponsors_readable = True
    try:
        # the first agent alone tells whether sponsors can be read at all, before thousands of refused reads
        if agents:
            agents[0]["sponsors"] = sponsors(agents[0])
        for agent, found in zip(agents[1:], _parallel(sponsors, agents[1:]), strict=True):
            agent["sponsors"] = found
    except CollectionError as exc:
        sponsors_readable = False
        for agent in agents:  # half-read sponsors would make some agents look orphaned and others not
            agent.pop("sponsors", None)
        denied = any(code in str(exc) for code in (" -> 401", " -> 403"))
        warnings.append(
            "Sponsors of Entra Agent ID identities not readable"
            + (" (Microsoft currently documents AgentIdentity.ReadWrite.All for this read)" if denied else "")
            + f"; those agents are not reported as orphaned. [{exc}]"
        )
    for agent in agents:
        agent.setdefault("@odata.type", "#microsoft.graph.agentIdentity")
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
            full = graph.get(f"/v1.0/servicePrincipals/{_seg(msgraph.get('id'))}", {"$select": "appRoles"})
            graph_roles = {r["id"]: r["value"] for r in full.get("appRoles", [])}
            graph_assignments = [
                a for a in graph.paged_large(f"/v1.0/servicePrincipals/{_seg(msgraph.get('id'))}/appRoleAssignedTo")
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

    progress("Exchange Online and SharePoint Online application permissions")
    resource_assignments: dict[str, Optional[list[dict[str, Any]]]] = {}
    resource_roles: dict[str, dict[str, str]] = {}
    for app_id, name in RESOURCE_APIS.items():
        resource = next((sp for sp in sps if sp.get("appId") == app_id), None)
        if resource is None:
            resource_assignments[app_id] = []  # not in the tenant: nothing can be granted on it
            continue
        try:
            full = graph.get(f"/v1.0/servicePrincipals/{_seg(resource.get('id'))}", {"$select": "appRoles"})
            resource_roles[app_id] = {r["id"]: r["value"] for r in full.get("appRoles", []) if r.get("value")}
            resource_assignments[app_id] = [
                a for a in graph.paged_large(f"/v1.0/servicePrincipals/{_seg(resource.get('id'))}/appRoleAssignedTo")
                if a.get("principalType") == "ServicePrincipal"
            ]
        except CollectionError as exc:
            resource_assignments[app_id] = None
            warnings.append(f"{name} application permissions not read (needs Application.Read.All). [{exc}]")
    if any(v is not None for v in resource_assignments.values()):
        read_at[SRC_RESOURCE_PERMISSIONS] = _now()

    progress("Federated credentials of app registrations")
    app_fic: Optional[dict[str, list[dict[str, Any]]]] = {}
    try:
        app_fic = _read_app_federation(graph, apps)
        read_at[SRC_FEDERATED_APPS] = _now()
    except CollectionError as exc:
        app_fic = None
        warnings.append(f"Federated credentials of app registrations not read (needs Application.Read.All); "
                        f"the federation rule skips them. [{exc}]")

    progress("Delegated permission grants")
    delegated: Optional[list[dict[str, Any]]] = None
    try:
        delegated = list(graph.paged_large("/v1.0/oauth2PermissionGrants"))
        read_at[SRC_DELEGATED_GRANTS] = _now()
    except CollectionError as exc:
        warnings.append(
            "Delegated permission grants not read (needs Directory.Read.All or DelegatedPermissionGrant.Read.All); "
            f"consent rules skipped. [{exc}]"
        )

    progress("Directory roles")
    role_defs: dict[str, dict[str, Any]] = {}
    role_assignments: Optional[list[dict[str, Any]]] = None
    user_roles: Optional[dict[str, list[dict[str, Any]]]] = None
    try:
        role_defs = {
            d["id"]: {"displayName": d["displayName"], "templateId": d.get("templateId")}
            for d in graph.paged("/v1.0/roleManagement/directory/roleDefinitions",
                                 {"$select": "id,displayName,templateId"})
        }
        sp_ids = {sp["id"] for sp in sps}
        assignments = list(graph.paged_large("/v1.0/roleManagement/directory/roleAssignments"))
        role_assignments = [a for a in assignments if a.get("principalId") in sp_ids]
        # a user who consents to an app lends it their own rights: keep the roles of those users too
        consenters = {g["principalId"] for g in delegated or [] if g.get("consentType") == "Principal" and g.get("principalId")}
        user_roles = {}
        for a in assignments:
            if a.get("principalId") in consenters:
                user_roles.setdefault(a["principalId"], []).append(a)
        read_at[SRC_DIRECTORY_ROLES] = _now()
    except CollectionError as exc:
        warnings.append(
            f"Entra directory roles not read (needs RoleManagement.Read.Directory); role rule skipped. [{exc}]"
        )

    def consenting_user(uid: str) -> Optional[dict[str, Any]]:
        try:  # only consenting users who hold a role
            return graph.get(f"/v1.0/users/{_seg(uid)}", {"$select": "id,userPrincipalName,accountEnabled"})
        except CollectionError:
            return None  # the id still identifies them

    uids = sorted(user_roles or {})
    consenting_users = {uid: u for uid, u in zip(uids, _parallel(consenting_user, uids), strict=True) if u is not None}

    progress("Service principal sign-in activity")
    signin: Optional[dict[str, Optional[datetime]]]
    try:
        signin = {
            row["appId"]: parse_graph_datetime((row.get("lastSignInActivity") or {}).get("lastSignInDateTime"))
            for row in graph.paged_large("/beta/reports/servicePrincipalSignInActivities")
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
    ai_accounts: Optional[list[dict[str, Any]]] = None
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
        progress("Azure OpenAI and AI Services accounts")
        try:
            ai_accounts = _collect_ai_accounts(_Http(credential, f"{ARM}/.default", ARM, tenant_id), warnings)
            read_at[SRC_AI_ACCOUNTS] = _now()
        except Exception as exc:  # noqa: BLE001 — optional
            warnings.append(f"Azure OpenAI and AI Services accounts not read: {exc}")

    return TenantSnapshot(
        tenant_id=org["id"],
        tenant_name=org.get("displayName") or org["id"],
        collected_at=_now(),
        applications=apps,
        service_principals=sps,
        graph_app_role_assignments=graph_assignments,
        graph_app_roles=graph_roles,
        resource_app_role_assignments=resource_assignments,
        resource_app_roles=resource_roles,
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
        ai_accounts=ai_accounts,
        consenting_user_roles=user_roles,
        consenting_users=consenting_users,
    )


def _read_directory(
    graph: _Http, progress: Callable[[str], None], read_at: dict[str, datetime],
    app_select: str, sp_select: str, owner_expand: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    progress("App registrations")
    apps = list(graph.paged_large("/v1.0/applications", {"$select": app_select, "$expand": owner_expand}))
    read_at[SRC_APPLICATIONS] = _now()

    progress("Service principals")
    sps = list(graph.paged_large("/v1.0/servicePrincipals", {"$select": sp_select, "$expand": owner_expand}))
    read_at[SRC_SERVICE_PRINCIPALS] = _now()
    return apps, sps


def _read_app_federation(graph: _Http, apps: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Federated credentials of every app registration: one listing with the relationship expanded, then one read per
    app only for the apps that listing did not cover. On 30,000 apps that is 31 requests instead of 30,000."""
    out: dict[str, list[dict[str, Any]]] = {}
    ids = {app["id"] for app in apps}
    try:
        for row in graph.paged_large("/v1.0/applications",
                                     {"$select": "id", "$expand": "federatedIdentityCredentials"}):
            fics = row.get("federatedIdentityCredentials")
            if row.get("id") in ids and isinstance(fics, list):
                out[row["id"]] = fics
    except CollectionError:
        out = {}  # the expanded listing is an optimisation: the reads one by one below give the same answer
    missing = [app["id"] for app in apps if app["id"] not in out]
    def one(app_id: str) -> list[dict[str, Any]]:
        return list(graph.paged(f"/v1.0/applications/{_seg(app_id)}/federatedIdentityCredentials"))

    found = _parallel(one, missing)
    out.update(zip(missing, found, strict=True))
    return {app["id"]: out[app["id"]] for app in apps}


def _collect_mi_federation(arm: _Http, warnings: list[str]) -> dict[str, list[dict[str, Any]]]:
    """Federated credentials of every user-assigned managed identity, keyed by its service principal id."""
    out: dict[str, list[dict[str, Any]]] = {}
    subs = list(arm.paged("/subscriptions", {"api-version": "2022-12-01"}))
    unreadable = 0
    for sub in subs:
        try:
            sub_id = _seg(sub.get("subscriptionId"))
            identities = list(arm.paged(
                f"/subscriptions/{sub_id}/providers/Microsoft.ManagedIdentity/userAssignedIdentities",
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
                    for f in arm.paged(f"{_mi_path(mi.get('id'))}/federatedIdentityCredentials",
                                       {"api-version": MANAGED_IDENTITY_API})
                ]
        except CollectionError as exc:
            unreadable += 1
            warnings.append(f"Managed identity federated credentials not read for subscription {sub['subscriptionId']}. [{exc}]")
    if subs and unreadable == len(subs):
        raise CollectionError("no subscription could be read")
    return out


def _collect_ai_accounts(arm: _Http, warnings: list[str]) -> list[dict[str, Any]]:
    """Azure OpenAI and AI Services accounts, with how they accept authentication. Keys themselves are never read."""
    out: list[dict[str, Any]] = []
    subs = list(arm.paged("/subscriptions", {"api-version": "2022-12-01"}))
    unreadable = 0
    for sub in subs:
        try:
            sub_id = _seg(sub.get("subscriptionId"))
            accounts = list(arm.paged(f"/subscriptions/{sub_id}/providers/Microsoft.CognitiveServices/accounts",
                                      {"api-version": COGNITIVE_SERVICES_API}))
        except CollectionError as exc:
            unreadable += 1
            warnings.append(f"AI accounts not read for subscription {sub['subscriptionId']}. [{exc}]")
            continue
        for a in accounts:
            if a.get("kind") not in AI_KINDS:
                continue
            props = a.get("properties") or {}
            out.append({
                "id": a["id"], "name": a.get("name") or a["id"].rsplit("/", 1)[-1], "kind": a.get("kind"),
                "location": a.get("location"), "endpoint": props.get("endpoint"), "sku": (a.get("sku") or {}).get("name"),
                "disable_local_auth": props.get("disableLocalAuth") is True,
                "public_network_access": props.get("publicNetworkAccess"),
                "network_default_action": (props.get("networkAcls") or {}).get("defaultAction"),
            })
    if subs and unreadable == len(subs):
        raise CollectionError("no subscription could be read")
    return out


def _collect_azure_rbac(arm: _Http, warnings: list[str]) -> list[dict[str, Any]]:
    """Role assignments of every readable subscription; one unreadable subscription only costs a warning."""
    out: dict[str, dict[str, Any]] = {}
    subs = list(arm.paged("/subscriptions", {"api-version": "2022-12-01"}))
    unreadable = 0
    for sub in subs:
        base = f"/subscriptions/{_seg(sub.get('subscriptionId'))}/providers/Microsoft.Authorization"
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

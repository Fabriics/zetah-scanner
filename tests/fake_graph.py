"""A Microsoft Graph that serves a ``TenantSnapshot``, for scale tests of the collector (T-14).

It answers the GET requests the collector sends, at the level of ``requests.Session.get``, so paging, $top, the host
check on paging links and the retries on 429 are the real code. Latency and throttling are simulated:

- each response waits ``base_latency`` plus ``per_object`` seconds for every object in it;
- with $expand a page holds at most 100 objects even when $top asks for 999, as Graph does;
- a token bucket refuses requests with 429 and Retry-After past ``ru_per_10s`` resource units every 10 seconds,
  the identity and access limit Microsoft documents for the largest tenants (8,000). Listings of applications and
  service principals cost 2 units, every other read 1.

The numbers are assumptions stated in the scale report, not measurements of Graph.
"""

from __future__ import annotations

import copy
import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from urllib.parse import parse_qsl, urlsplit

from src.nhi_scanner.collector import AGENT_IDENTITIES, GRAPH
from src.nhi_scanner.snapshot import TenantSnapshot

DEFAULT_PAGE = 100
MAX_PAGE = 999


@dataclass
class Stats:
    requests: int = 0
    throttled: int = 0
    by_kind: dict[str, int] = field(default_factory=dict)

    def count(self, kind: str) -> None:
        self.by_kind[kind] = self.by_kind.get(kind, 0) + 1


class FakeResponse:
    def __init__(self, status: int, body: Any = None, headers: Optional[dict[str, str]] = None):
        self.status_code = status
        self.headers = headers or {}
        self._body = body
        self.text = json.dumps(body)[:300] if body is not None else ""

    def json(self) -> Any:
        return self._body


def _ts(d: Optional[datetime]) -> Optional[str]:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else None


class FakeGraph:
    def __init__(self, snap: TenantSnapshot, *, base_latency: float = 0.0, per_object: float = 0.0,
                 ru_per_10s: Optional[int] = None, burst: Optional[int] = None, expand_federation: bool = True, top_supported: bool = True):
        self.base_latency, self.per_object = base_latency, per_object
        self.ru_per_10s = ru_per_10s
        self.expand_federation, self.top_supported = expand_federation, top_supported
        self.stats = Stats()
        self._lock = threading.Lock()
        self._tokens = float(ru_per_10s or 0 if burst is None else burst)  # a full bucket, unless told otherwise
        self._refilled = time.monotonic()

        agents = [sp for sp in snap.service_principals if sp.get("@odata.type", "").endswith("agentIdentity")]
        agent_ids = {a["id"] for a in agents}
        self.sponsors = {a["id"]: a.get("sponsors", []) for a in agents}
        strip = lambda sp: {k: v for k, v in sp.items() if k != "sponsors"}  # noqa: E731
        self.lists: dict[str, list[dict[str, Any]]] = {
            "/v1.0/applications": snap.applications,
            "/v1.0/servicePrincipals": [sp for sp in snap.service_principals if sp["id"] not in agent_ids],
            AGENT_IDENTITIES: [strip(a) for a in agents],
            "/v1.0/oauth2PermissionGrants": snap.delegated_permission_grants or [],
            "/v1.0/roleManagement/directory/roleDefinitions": [
                {"id": k, **v} for k, v in snap.directory_role_definitions.items()],
            "/v1.0/roleManagement/directory/roleAssignments": (snap.directory_role_assignments or []) + [
                a for rows in (snap.consenting_user_roles or {}).values() for a in rows],
            "/beta/reports/servicePrincipalSignInActivities": [
                {"appId": app_id, "lastSignInActivity": {"lastSignInDateTime": _ts(d)}}
                for app_id, d in (snap.signin_activity or {}).items()],
            "/subscriptions": [],
        }
        self.fic = snap.app_federated_credentials or {}
        self.app_roles: dict[str, list[dict[str, Any]]] = {}
        self.assigned_to: dict[str, list[dict[str, Any]]] = {}
        by_app_id = {sp["appId"]: sp["id"] for sp in snap.service_principals}
        resources = [(by_app_id.get("00000003-0000-0000-c000-000000000000"), snap.graph_app_roles,
                      snap.graph_app_role_assignments or [])]
        for api, rows in (snap.resource_app_role_assignments or {}).items():
            resources.append((by_app_id.get(api), snap.resource_app_roles.get(api, {}), rows or []))
        for sp_id, roles, rows in resources:
            if sp_id:
                self.app_roles[sp_id] = [{"id": k, "value": v} for k, v in roles.items()]
                self.assigned_to[sp_id] = list(rows)
        self.users = {uid: {"id": uid, **u} for uid, u in snap.consenting_users.items()}
        self.org = {"id": snap.tenant_id, "displayName": snap.tenant_name}
        self._cursors: dict[str, tuple[list[dict[str, Any]], int, int]] = {}

    # ---- the transport ---------------------------------------------------------------------------------------- #

    def get(self, url: str, params: Optional[dict[str, str]] = None, **_kwargs: Any) -> FakeResponse:
        parts = urlsplit(url)
        base = urlsplit(GRAPH)
        if (parts.scheme, parts.hostname) != (base.scheme, base.hostname):
            return FakeResponse(200, {"value": []})  # ARM: no subscriptions in this tenant
        query = dict(parse_qsl(parts.query)) | dict(params or {})
        cost = 2 if parts.path in ("/v1.0/applications", "/v1.0/servicePrincipals") else 1
        wait = self._take(cost)
        if wait:
            with self._lock:
                self.stats.throttled += 1
            return FakeResponse(429, {"error": {"code": "TooManyRequests"}}, {"Retry-After": f"{wait:.2f}"})
        status, body = self._route(parts.path, query)
        objects = len(body.get("value", [])) if isinstance(body, dict) else 0
        time.sleep(self.base_latency + self.per_object * objects)
        with self._lock:
            self.stats.requests += 1
            self.stats.count(self._kind(parts.path))
        return FakeResponse(status, copy.deepcopy(body))

    def _take(self, cost: int) -> float:
        if not self.ru_per_10s:
            return 0.0
        with self._lock:
            now = time.monotonic()
            self._tokens = min(self.ru_per_10s, self._tokens + (now - self._refilled) * self.ru_per_10s / 10)
            self._refilled = now
            if self._tokens >= cost:
                self._tokens -= cost
                return 0.0
            return (cost - self._tokens) * 10 / self.ru_per_10s

    @staticmethod
    def _kind(path: str) -> str:
        if path.endswith("/federatedIdentityCredentials"):
            return "federated credentials, one app"
        if path.endswith("/sponsors"):
            return "sponsors, one agent"
        if path.startswith("/v1.0/users/"):
            return "user"
        return "listing page"

    # ---- the routes ------------------------------------------------------------------------------------------- #

    def _route(self, path: str, query: dict[str, str]) -> tuple[int, Any]:
        if "$skiptoken" in query:
            return 200, self._page(*self._cursors[query["$skiptoken"]], path, query)
        if "$top" in query and not self.top_supported:
            return 400, {"error": {"code": "Request_UnsupportedQuery", "message": "$top"}}
        if path == "/v1.0/organization":
            return 200, {"value": [self.org]}
        if path == "/v1.0/applications" and query.get("$expand") == "federatedIdentityCredentials":
            if not self.expand_federation:
                return 400, {"error": {"code": "Request_BadRequest", "message": "expand"}}
            rows = [{"id": a["id"], "federatedIdentityCredentials": self.fic.get(a["id"], [])}
                    for a in self.lists["/v1.0/applications"]]
            return 200, self._first(rows, path, query)
        if path in self.lists:
            return 200, self._first(self.lists[path], path, query)
        if path.startswith("/v1.0/applications/") and path.endswith("/federatedIdentityCredentials"):
            return 200, {"value": self.fic.get(path.split("/")[3], [])}
        if path.endswith("/microsoft.graph.agentIdentity/sponsors"):
            return 200, {"value": self.sponsors.get(path.split("/")[3], [])}
        if path.endswith("/appRoleAssignedTo"):
            return 200, self._first(self.assigned_to.get(path.split("/")[3], []), path, query)
        if path.startswith("/v1.0/servicePrincipals/"):
            return 200, {"appRoles": self.app_roles.get(path.split("/")[3], [])}
        if path.startswith("/v1.0/users/"):
            user = self.users.get(path.split("/")[3])
            return (200, user) if user else (404, {"error": {"code": "Request_ResourceNotFound"}})
        return 404, {"error": {"code": "NotFound", "message": path}}

    def _first(self, rows: list[dict[str, Any]], path: str, query: dict[str, str]) -> dict[str, Any]:
        # with $expand Graph returns at most 100 objects a page, whatever $top asks (seen on a live tenant, 26/11/2026)
        size = min(int(query.get("$top", DEFAULT_PAGE)), DEFAULT_PAGE if "$expand" in query else MAX_PAGE)
        return self._page(rows, 0, size, path, query)

    def _page(self, rows: list[dict[str, Any]], start: int, size: int, path: str, query: dict[str, str]) -> dict:
        body: dict[str, Any] = {"value": rows[start:start + size]}
        if start + size < len(rows):
            with self._lock:
                token = f"t{len(self._cursors)}"
                self._cursors[token] = (rows, start + size, size)
            body["@odata.nextLink"] = f"{GRAPH}{path}?$skiptoken={token}"
        return body


def install(monkeypatch: Any, graph: FakeGraph) -> None:
    """Route every HTTP GET of the collector to ``graph``, with a credential that never signs in anywhere."""
    import sys
    import types

    import requests

    class _Credential:
        def __init__(self, **_kwargs: Any):
            pass

        def get_token(self, *_scopes: str, **_kwargs: Any) -> Any:
            return types.SimpleNamespace(token="t", expires_on=10**12)

    monkeypatch.setitem(sys.modules, "azure.identity", types.SimpleNamespace(DefaultAzureCredential=_Credential))
    monkeypatch.setattr(requests.Session, "get", graph.get)

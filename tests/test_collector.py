"""Live collector wiring against canned Graph/ARM responses (no network)."""

import copy
import logging
import sys
import types

import pytest
import requests

from src.nhi_scanner import collector
from src.nhi_scanner.engine import run_scan

TENANT = "11111111-1111-4111-8111-111111111111"
GRAPH_SP = "22222222-0000-4000-8000-000000000001"
APP_SP = "22222222-0000-4000-8000-000000000002"
ROLE_ID = "33333333-0000-4000-8000-000000000001"
AGENT_SPONSORED = "44444444-0000-4000-8000-000000000001"
AGENT_LONELY = "44444444-0000-4000-8000-000000000002"
BLUEPRINT_SP = "44444444-0000-4000-8000-000000000003"

ROUTES = {
    "/v1.0/organization": {"value": [{"id": TENANT, "displayName": "Contoso Test"}]},
    "/v1.0/applications": {
        "value": [{
            "id": "app-obj-1", "appId": "app-1", "displayName": "etl-runner",
            "createdDateTime": "2023-01-01T00:00:00Z", "signInAudience": "AzureADMyOrg", "tags": [],
            "passwordCredentials": [{"keyId": "k1", "displayName": "s", "startDateTime": "2025-01-01T00:00:00.1234567Z",
                                     "endDateTime": "2099-01-01T00:00:00Z"}],
            "keyCredentials": [], "owners": [],
        }],
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/applications?$skiptoken=page2",
    },
    "https://graph.microsoft.com/v1.0/applications?$skiptoken=page2": {"value": []},
    "/v1.0/servicePrincipals": {"value": [
        {"id": GRAPH_SP, "appId": collector.MS_GRAPH_APP_ID, "displayName": "Microsoft Graph",
         "appOwnerOrganizationId": "f8cdef31-a31e-4b4a-93e4-5f571e91255a", "servicePrincipalType": "Application"},
        {"id": APP_SP, "appId": "app-1", "displayName": "etl-runner", "servicePrincipalType": "Application",
         "accountEnabled": True, "appOwnerOrganizationId": TENANT, "owners": []},
        {"@odata.type": "#microsoft.graph.agentIdentityBlueprintPrincipal", "id": BLUEPRINT_SP, "appId": "bp-1",
         "displayName": "hr-agent-blueprint", "servicePrincipalType": "Application", "appOwnerOrganizationId": TENANT,
         "owners": [{"id": "u1", "userPrincipalName": "owner@contoso.example"}]},
    ]},
    collector.AGENT_IDENTITIES: {"value": [
        {"@odata.type": "#microsoft.graph.agentIdentity", "id": AGENT_SPONSORED, "appId": "ag-1",
         "displayName": "hr-onboarding", "servicePrincipalType": "ServiceIdentity", "agentIdentityBlueprintId": "bp-1",
         "appOwnerOrganizationId": TENANT, "owners": []},
        {"@odata.type": "#microsoft.graph.agentIdentity", "id": AGENT_LONELY, "appId": "ag-2",
         "displayName": "expense-checker", "servicePrincipalType": "ServiceIdentity", "agentIdentityBlueprintId": "bp-1",
         "appOwnerOrganizationId": TENANT, "owners": []},
    ]},
    f"/beta/servicePrincipals/{AGENT_SPONSORED}/microsoft.graph.agentIdentity/sponsors": {
        "value": [{"id": "u2", "userPrincipalName": "sponsor@contoso.example"}]},
    f"/beta/servicePrincipals/{AGENT_LONELY}/microsoft.graph.agentIdentity/sponsors": {"value": []},
    f"/v1.0/servicePrincipals/{GRAPH_SP}": {"appRoles": [{"id": ROLE_ID, "value": "Application.ReadWrite.All"}]},
    f"/v1.0/servicePrincipals/{GRAPH_SP}/appRoleAssignedTo": {"value": [
        {"id": "ara-1", "principalId": APP_SP, "principalType": "ServicePrincipal", "appRoleId": ROLE_ID},
        {"id": "ara-2", "principalId": "some-group", "principalType": "Group", "appRoleId": ROLE_ID},
    ]},
    "/v1.0/roleManagement/directory/roleDefinitions": {"value": []},
    "/v1.0/roleManagement/directory/roleAssignments": {"value": []},
    "/subscriptions": {"value": []},
}


class FakeCredential:
    def __init__(self, **_kwargs):
        pass

    def get_token(self, *_scopes, **_kwargs):
        return types.SimpleNamespace(token="t", expires_on=10**12)


@pytest.fixture
def fake_backend(monkeypatch):
    return _backend(monkeypatch)


def _backend(monkeypatch, forbidden=(), routes=None, signin_readable=False):
    monkeypatch.setitem(sys.modules, "azure.identity", types.SimpleNamespace(DefaultAzureCredential=FakeCredential))
    all_routes = {**ROUTES, **(routes or {})}

    def get(self, url, params=None):
        signin_denied = url == "/beta/reports/servicePrincipalSignInActivities" and not signin_readable
        if signin_denied or any(f in url for f in forbidden):
            raise collector.CollectionError(f"GET {url} -> 403: Forbidden")
        return copy.deepcopy(all_routes[url])  # like a real response: a fresh object every call

    monkeypatch.setattr(collector._Http, "get", get)


def test_collect_builds_a_scannable_snapshot(fake_backend):
    snap = collector.collect()
    assert snap.tenant_id == TENANT and snap.tenant_name == "Contoso Test"
    assert [a["id"] for a in snap.graph_app_role_assignments] == ["ara-1"]  # groups filtered out
    assert snap.signin_activity is None
    assert any("Sign-in activity unavailable" in w for w in snap.warnings)
    assert snap.azure_role_assignments == []

    payload = run_scan(snap)
    assert payload.metadata.tenant_id == TENANT
    assert payload.metadata.collection_warnings == snap.warnings
    assert not any(r.startswith("NHI-DORM") for r in payload.metadata.rules_evaluated)
    assert ("NHI-PERM-001", "etl-runner") in {(f.rule_id, f.entity_name) for f in payload.findings}
    assert all(e.display_name != "Microsoft Graph" for e in payload.entities)


def _agents(payload):
    return {e.display_name: e for e in payload.entities if e.entity_type.value == "ai_agent"}


def _orphan_findings(payload):
    return {f.entity_name for f in payload.findings if f.rule_id == "NHI-AGENT-001"}


def test_entra_agent_id_identities_and_sponsors(fake_backend):
    snap = collector.collect()
    payload = run_scan(snap)
    agents = _agents(payload)
    assert {"hr-onboarding", "expense-checker", "hr-agent-blueprint"} <= set(agents)
    assert agents["hr-onboarding"].raw_metadata["agent_classification_signals"][0] == "entra_agent_id"
    assert agents["hr-agent-blueprint"].raw_metadata["agent_classification_signals"][0] == "entra_agent_blueprint"
    assert agents["hr-onboarding"].owners == ["sponsor@contoso.example"]  # a sponsor is an accountable owner
    assert agents["hr-onboarding"].raw_metadata["agent_identity_blueprint_id"] == "bp-1"
    assert _orphan_findings(payload) == {"expense-checker"}  # no owner, no sponsor


def test_unreadable_sponsors_are_unknown_not_orphaned(monkeypatch):
    _backend(monkeypatch, forbidden=("/sponsors",))
    snap = collector.collect()
    assert any("Sponsors of Entra Agent ID identities not readable" in w for w in snap.warnings)
    payload = run_scan(snap)
    assert _orphan_findings(payload) == set()
    assert _agents(payload)["expense-checker"].raw_metadata["sponsors_unknown"] is True


def test_missing_agent_id_permission_is_a_warning(monkeypatch):
    _backend(monkeypatch, forbidden=(collector.AGENT_IDENTITIES,))
    snap = collector.collect()
    assert any("needs AgentIdentity.Read.All" in w for w in snap.warnings)
    assert "hr-onboarding" not in _agents(run_scan(snap))


def test_empty_signin_report_is_unknown_not_never_used(monkeypatch):
    _backend(monkeypatch, routes={"/beta/reports/servicePrincipalSignInActivities": {"value": []}}, signin_readable=True)
    snap = collector.collect()
    assert snap.signin_activity is None
    assert any("Sign-in activity report is empty" in w for w in snap.warnings)
    payload = run_scan(snap)
    assert not any(r.startswith("NHI-DORM") for r in payload.metadata.rules_evaluated)


def test_signin_rows_are_used_when_present(monkeypatch):
    rows = {"value": [{"appId": "app-1", "lastSignInActivity": {"lastSignInDateTime": "2026-10-01T00:00:00Z"}}]}
    _backend(monkeypatch, routes={"/beta/reports/servicePrincipalSignInActivities": rows}, signin_readable=True)
    snap = collector.collect()
    assert set(snap.signin_activity) == {"app-1"}
    assert not any("Sign-in activity" in w for w in snap.warnings)


def test_credential_gets_a_generous_timeout_and_a_quiet_logger(monkeypatch):
    seen = {}

    class Recording(FakeCredential):
        def __init__(self, **kwargs):
            seen.update(kwargs)

    _backend(monkeypatch)
    monkeypatch.setitem(sys.modules, "azure.identity", types.SimpleNamespace(DefaultAzureCredential=Recording))
    collector.collect()
    assert seen["process_timeout"] == 60
    assert logging.getLogger("azure.identity").level == logging.CRITICAL


def test_missing_graph_permission_data_skips_only_its_rules(monkeypatch):
    _backend(monkeypatch, forbidden=("appRoleAssignedTo",))
    snap = collector.collect()
    assert snap.graph_app_role_assignments is None
    assert any("Microsoft Graph application permissions not read" in w for w in snap.warnings)
    evaluated = run_scan(snap).metadata.rules_evaluated
    assert not {"NHI-PERM-001", "NHI-PERM-002", "NHI-AGENT-002", "NHI-AGENT-003"} & set(evaluated)
    assert {"NHI-PERM-003", "NHI-SEC-002"} <= set(evaluated)


def test_missing_directory_roles_skip_only_the_role_rule(monkeypatch):
    _backend(monkeypatch, forbidden=("/roleManagement/",))
    snap = collector.collect()
    assert snap.directory_role_assignments is None
    assert any("Entra directory roles not read" in w for w in snap.warnings)
    evaluated = run_scan(snap).metadata.rules_evaluated
    assert "NHI-PERM-003" not in evaluated and "NHI-PERM-001" in evaluated


def test_unreadable_organization_falls_back_to_the_given_tenant(monkeypatch):
    _backend(monkeypatch, forbidden=("/v1.0/organization",))
    snap = collector.collect(tenant_id=TENANT)
    assert snap.tenant_id == TENANT and any("Tenant details not read" in w for w in snap.warnings)
    with pytest.raises(collector.CollectionError, match="--tenant-id"):
        collector.collect()


def test_scan_without_app_registrations_stops_with_a_clear_reason(monkeypatch):
    _backend(monkeypatch, forbidden=("/v1.0/applications",))
    with pytest.raises(collector.CollectionError, match="needs Application.Read.All"):
        collector.collect()


def _sub_routes(*sub_ids):
    routes = {"/subscriptions": {"value": [{"subscriptionId": s} for s in sub_ids]}}
    for s in sub_ids:
        base = f"/subscriptions/{s}/providers/Microsoft.Authorization"
        routes[f"{base}/roleDefinitions"] = {"value": [{"name": "r1", "properties": {"roleName": "Owner"}}]}
        routes[f"{base}/roleAssignments"] = {"value": [{"id": f"{base}/roleAssignments/a", "properties": {
            "principalType": "ServicePrincipal", "principalId": APP_SP, "scope": f"/subscriptions/{s}",
            "roleDefinitionId": ".../r1"}}]}
    return routes


def test_one_unreadable_subscription_keeps_the_others(monkeypatch):
    _backend(monkeypatch, forbidden=("/subscriptions/sub-b/",), routes=_sub_routes("sub-a", "sub-b"))
    snap = collector.collect()
    assert [a["scope"] for a in snap.azure_role_assignments] == ["/subscriptions/sub-a"]
    assert any("Azure RBAC not read for subscription sub-b" in w for w in snap.warnings)


def test_no_readable_subscription_means_azure_was_not_scanned(monkeypatch):
    _backend(monkeypatch, forbidden=("/subscriptions/sub-",), routes=_sub_routes("sub-a", "sub-b"))
    snap = collector.collect()
    assert snap.azure_role_assignments is None
    assert any("Azure RBAC not scanned" in w for w in snap.warnings)


def _http_with(session_get, monkeypatch):
    monkeypatch.setattr(collector.time, "sleep", lambda _seconds: None)
    http = collector._Http(FakeCredential(), "scope", "https://graph.test")
    http._session = types.SimpleNamespace(get=session_get)
    return http


def test_network_errors_are_retried(monkeypatch):
    calls = []

    def flaky(url, **_kwargs):
        calls.append(url)
        if len(calls) < 3:
            raise requests.ConnectionError("connection reset")
        return types.SimpleNamespace(status_code=200, json=lambda: {"ok": True})

    assert _http_with(flaky, monkeypatch).get("/v1.0/x") == {"ok": True}
    assert len(calls) == 3


def test_a_lasting_network_failure_is_a_collection_error(monkeypatch):
    def down(_url, **_kwargs):
        raise requests.Timeout("timed out")

    with pytest.raises(collector.CollectionError, match="timed out"):
        _http_with(down, monkeypatch).get("/v1.0/x")

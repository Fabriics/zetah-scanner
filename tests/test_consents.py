"""Delegated consents to AI clients: NHI-AGENT-006 (read and send) and NHI-AGENT-008 (offline access)."""

from datetime import datetime, timezone

import pytest

from src.nhi_scanner.demo import build_demo_snapshot
from src.nhi_scanner.engine import run_scan
from src.nhi_scanner.models import EntityType, SectionStatus, Severity

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)


def sp_id(snap, name):
    return next(sp["id"] for sp in snap.service_principals if sp["displayName"] == name)


def grant(snap, client, scope, user=None, resource="Microsoft Graph", gid=None):
    return {"id": gid or f"g-{client}-{user or 'all'}-{resource}", "clientId": sp_id(snap, client),
            "resourceId": sp_id(snap, resource), "consentType": "Principal" if user else "AllPrincipals",
            "principalId": user, "scope": scope}


def findings(payload, rule_id):
    return {f.entity_name: f for f in payload.findings if f.rule_id == rule_id}


def scan_with(*grants_of):
    snap = build_demo_snapshot(NOW)
    snap.delegated_permission_grants = [g(snap) for g in grants_of]
    return run_scan(snap, now=NOW)


@pytest.fixture(scope="module")
def demo():
    return run_scan(build_demo_snapshot(NOW), now=NOW)


def test_third_party_ai_client_with_read_and_send(demo):
    f = findings(demo, "NHI-AGENT-006")["Nimbus AI Assistant"]
    assert f.severity is Severity.MEDIUM  # consented by users for themselves, not tenant-wide
    assert (f.evidence["all_users"], f.evidence["user_count"]) == (False, 2)
    assert f.evidence["read_scopes"] == ["Files.Read.All", "Mail.Read"]
    assert f.evidence["egress_scopes"] == ["Mail.Send"]
    assert f.evidence["external_app"] is True
    assert "third party" in f.attack_path_context
    # the Azure consent is not part of this path, so it is not revoked here
    assert len(f.evidence["grant_ids"]) == 2 and f.remediation_cli.count("--method DELETE") == 2


def test_offline_access_on_sensitive_scopes(demo):
    hits = findings(demo, "NHI-AGENT-008")
    nimbus = hits["Nimbus AI Assistant"]
    assert nimbus.severity is Severity.HIGH  # published by another organization
    assert nimbus.evidence["user_count"] == 2  # the calendar-only user is not counted
    assert "Azure Resource Manager user_impersonation" in nimbus.evidence["scopes"]
    assert len(nimbus.evidence["grant_ids"]) == 3

    helpdesk = hits["Helpdesk Assistant"]
    assert helpdesk.severity is Severity.HIGH and helpdesk.evidence["all_users"] is True
    assert helpdesk.evidence["scopes"] == ["offline_access", "Sites.Read.All"]
    assert "Helpdesk Assistant" not in findings(demo, "NHI-AGENT-006")  # it reads, but cannot send


def test_clients_that_are_not_ai_agents_are_recorded_not_judged(demo):
    payments = next(e for e in demo.entities
                    if e.display_name == "payments-api" and e.entity_type is EntityType.SERVICE_PRINCIPAL)
    assert [(d.resource, d.scope, d.all_users) for d in payments.record.delegated_permissions.items] == [
        ("Microsoft Graph", "User.Read", True)]
    assert not [f for f in demo.findings if f.entity_id == payments.entity_id and f.rule_id.startswith("NHI-AGENT")]


def test_tenant_wide_read_and_send_is_high():
    p = scan_with(lambda s: grant(s, "Nimbus AI Assistant", "Mail.Read Mail.Send"))
    f = findings(p, "NHI-AGENT-006")["Nimbus AI Assistant"]
    assert f.severity is Severity.HIGH and f.evidence["all_users"] is True
    assert "every user of the tenant" in f.description
    assert "Nimbus AI Assistant" not in findings(p, "NHI-AGENT-008")  # no offline_access


def test_a_user_path_can_combine_tenant_and_personal_consents():
    p = scan_with(
        lambda s: grant(s, "Nimbus AI Assistant", "Mail.Read"),
        lambda s: grant(s, "Nimbus AI Assistant", "Mail.Send", user="u-1"),
        lambda s: grant(s, "Nimbus AI Assistant", "User.Read", user="u-2"),
    )
    f = findings(p, "NHI-AGENT-006")["Nimbus AI Assistant"]
    assert (f.evidence["all_users"], f.evidence["user_ids"]) == (False, ["u-1"])
    # both grants make the path; the other user's User.Read grant does not
    assert sorted(f.evidence["grant_ids"]) == ["g-Nimbus AI Assistant-all-Microsoft Graph",
                                               "g-Nimbus AI Assistant-u-1-Microsoft Graph"]


def test_scope_names_are_case_insensitive_and_other_apis_do_not_count():
    p = scan_with(lambda s: grant(s, "Nimbus AI Assistant", "mail.read MAIL.SEND", user="u-1"))
    assert findings(p, "NHI-AGENT-006")["Nimbus AI Assistant"].evidence["read_scopes"] == ["Mail.Read"]
    # same scope names on an API that is not Microsoft Graph
    p = scan_with(lambda s: grant(s, "Nimbus AI Assistant", "Mail.Read Mail.Send offline_access", user="u-1",
                                  resource="Acme Cloud Backup"))
    assert not findings(p, "NHI-AGENT-006") and not findings(p, "NHI-AGENT-008")


@pytest.mark.parametrize("owners, severity", [(["it-ops@demo-corp.example"], Severity.MEDIUM), ([], Severity.HIGH)])
def test_in_house_agent_severity_depends_on_its_owner(owners, severity):
    snap = build_demo_snapshot(NOW)
    for obj in snap.applications + snap.service_principals:
        if obj["displayName"] == "Helpdesk Assistant":
            obj["owners"] = [{"@odata.type": "#microsoft.graph.user", "id": o, "userPrincipalName": o} for o in owners]
    snap.delegated_permission_grants = [grant(snap, "Helpdesk Assistant", "offline_access Files.Read", user="u-1")]
    f = findings(run_scan(snap, now=NOW), "NHI-AGENT-008")["Helpdesk Assistant"]
    assert f.severity is severity and f.evidence["orphaned"] is (not owners)


def test_remediation_lists_at_most_fifty_grants_and_never_disables_the_app():
    p = scan_with(*[
        (lambda i: lambda s: grant(s, "Nimbus AI Assistant", "Mail.Read Mail.Send", user=f"u-{i:03}", gid=f"g{i:03}"))(i)
        for i in range(60)
    ])
    f = findings(p, "NHI-AGENT-006")["Nimbus AI Assistant"]
    assert f.evidence["user_count"] == 60 and len(f.evidence["user_ids"]) == 50
    live = [line for line in f.remediation_cli.splitlines() if not line.startswith("#")]
    assert len(live) == 50 and all("oauth2PermissionGrants/g0" in line for line in live)
    assert "...and 10 more" in f.remediation_cli
    assert "# az ad sp update" in f.remediation_cli and "accountEnabled=false" not in "\n".join(live)


def test_record_aggregates_consents_per_scope(demo):
    nimbus = next(e for e in demo.entities if e.display_name == "Nimbus AI Assistant").record.delegated_permissions
    assert nimbus.status is SectionStatus.READ and "own access" in nimbus.note
    by_scope = {(d.resource, d.scope): (d.all_users, d.user_count) for d in nimbus.items}
    assert by_scope[("Microsoft Graph", "offline_access")] == (False, 3)
    assert by_scope[("Microsoft Graph", "Files.Read.All")] == (False, 1)
    assert by_scope[("Windows Azure Service Management API", "user_impersonation")] == (False, 1)
    app = next(e for e in demo.entities
               if e.display_name == "Helpdesk Assistant" and e.entity_type is EntityType.APP_REGISTRATION)
    assert app.record.delegated_permissions.status is SectionStatus.NOT_APPLICABLE

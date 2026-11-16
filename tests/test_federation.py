"""Workload identity federation: federated credentials in the record, and NHI-SEC-006 on loose GitHub trusts."""

from datetime import datetime, timezone

import pytest

from src.nhi_scanner import collector
from src.nhi_scanner.demo import build_demo_snapshot
from src.nhi_scanner.engine import run_scan
from src.nhi_scanner.models import EntityType, SectionStatus, Severity
from src.nhi_scanner.rules import github_subject_risk

from test_collector import _backend

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def demo():
    return run_scan(build_demo_snapshot(NOW), now=NOW)


def finding(payload, name):
    return next((f for f in payload.findings if f.rule_id == "NHI-SEC-006" and f.entity_name == name), None)


def record(payload, name, etype):
    return next(e for e in payload.entities if e.display_name == name and e.entity_type is etype).record


@pytest.mark.parametrize("subject, severity", [
    ("repo:org/app:pull_request", Severity.HIGH),
    ("repo:org/app", Severity.HIGH),
    (None, Severity.HIGH),
    ("repo:org/app:environment:production", Severity.MEDIUM),
    ("repo:org/app:ref:refs/heads/feature-x", Severity.MEDIUM),
    ("repo:org/app:ref:refs/tags/v1.0", Severity.MEDIUM),
    ("repository_owner_id:1234:repository_id:5678", Severity.MEDIUM),
    ("repo:org/app:ref:refs/heads/main", None),
    ("repo:org/app:ref:refs/heads/master", None),
])
def test_github_subjects_are_judged_by_how_much_they_admit(subject, severity):
    risk = github_subject_risk(subject)
    assert (risk[0] if risk else None) is severity


def test_demo_findings_and_escalation_on_privileged_identities(demo):
    ci = finding(demo, "ci-deploy-pipeline")
    assert ci.severity is Severity.CRITICAL and ci.evidence["privileged"] is True  # pull_request on an Azure admin
    assert [c["subject"] for c in ci.evidence["credentials"]] == ["repo:demo-corp/infra:pull_request"]  # main is fine
    ida = finding(demo, "Identity Automation")
    assert ida.severity is Severity.HIGH  # an environment, raised one level by Privileged Role Administrator
    poc = finding(demo, "marketing-analytics-poc")
    assert poc.severity is Severity.HIGH and "flexible" in poc.description
    mi = finding(demo, "id-foundry-research-agent")
    assert mi.severity is Severity.MEDIUM and "--identity-name id-foundry-research-agent --resource-group rg-ai" in mi.remediation_cli
    assert finding(demo, "payments-api") is None and finding(demo, "id-aks-workload") is None


def test_remediation_never_runs_by_itself(demo):
    for f in demo.findings:
        if f.rule_id == "NHI-SEC-006":
            assert all(line.startswith("#") for line in f.remediation_cli.splitlines()), f.entity_name
    poc = finding(demo, "marketing-analytics-poc").remediation_cli
    assert "federated-credential create" in poc and "federated-credential delete" in poc  # flexible: replace it


def test_the_record_shows_every_trust_and_where_it_lives(demo):
    app = record(demo, "payments-api", EntityType.APP_REGISTRATION).federated_credentials
    sp = record(demo, "payments-api", EntityType.SERVICE_PRINCIPAL).federated_credentials
    assert app.status is SectionStatus.READ and [f.subject for f in app.items] == ["repo:demo-corp/payments:ref:refs/heads/main"]
    assert sp.items == app.items and sp.items[0].held_on == "application"
    aks = record(demo, "id-aks-workload", EntityType.MANAGED_IDENTITY).federated_credentials
    assert aks.items[0].issuer.startswith("https://oidc.prod-aks") and aks.items[0].held_on == "managed_identity"
    func = record(demo, "func-invoice-processor", EntityType.MANAGED_IDENTITY).federated_credentials
    assert func.status is SectionStatus.NOT_APPLICABLE  # system-assigned
    ext = next(e for e in demo.entities if e.display_name == "Acme Cloud Backup").record.federated_credentials
    assert ext.status is SectionStatus.NOT_APPLICABLE
    agent = record(demo, "Procurement Agent", EntityType.AI_AGENT).federated_credentials
    assert agent.status is SectionStatus.NOT_READ and "blueprint" in agent.note


def test_unread_credentials_are_unknown_and_skip_the_rule():
    snap = build_demo_snapshot(NOW)
    snap.app_federated_credentials = snap.mi_federated_credentials = None
    p = run_scan(snap, now=NOW)
    assert "NHI-SEC-006" not in p.metadata.rules_evaluated
    assert record(p, "payments-api", EntityType.APP_REGISTRATION).federated_credentials.status is SectionStatus.NOT_READ
    snap = build_demo_snapshot(NOW)
    snap.mi_federated_credentials = None  # apps read, Azure not: the rule still runs on app registrations
    p = run_scan(snap, now=NOW)
    assert "NHI-SEC-006" in p.metadata.rules_evaluated and finding(p, "id-foundry-research-agent") is None


SUB = "sub-1"
MI_ID = f"/subscriptions/{SUB}/resourceGroups/rg-ci/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-deployer"
ARM_ROUTES = {
    "/subscriptions": {"value": [{"subscriptionId": SUB}]},
    f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions": {"value": []},
    f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments": {"value": []},
    f"/subscriptions/{SUB}/providers/Microsoft.ManagedIdentity/userAssignedIdentities": {"value": [
        {"id": MI_ID, "name": "id-deployer", "properties": {"principalId": "mi-sp-1", "clientId": "mi-app-1"}}]},
    f"{MI_ID}/federatedIdentityCredentials": {"value": [
        {"id": f"{MI_ID}/federatedIdentityCredentials/gh", "name": "gh", "properties": {
            "issuer": "https://token.actions.githubusercontent.com", "subject": "repo:contoso/deploy:pull_request",
            "audiences": ["api://AzureADTokenExchange"]}}]},
}


def test_collector_reads_app_and_managed_identity_trusts(monkeypatch):
    _backend(monkeypatch, routes=ARM_ROUTES)
    snap = collector.collect()
    assert [f["subject"] for f in snap.app_federated_credentials["app-obj-1"]] == ["repo:contoso/etl:pull_request"]
    [mi] = snap.mi_federated_credentials["mi-sp-1"]
    assert (mi["name"], mi["subject"], mi["identity_id"]) == ("gh", "repo:contoso/deploy:pull_request", MI_ID)
    assert {collector.SRC_FEDERATED_APPS, collector.SRC_FEDERATED_MI} <= set(snap.read_at)
    assert finding(run_scan(snap), "etl-runner").severity is Severity.CRITICAL  # Application.ReadWrite.All holder


def test_unreadable_app_trusts_are_a_warning(monkeypatch):
    _backend(monkeypatch, forbidden=("/federatedIdentityCredentials",))
    snap = collector.collect()
    assert snap.app_federated_credentials is None
    assert any("Federated credentials of app registrations not read" in w for w in snap.warnings)

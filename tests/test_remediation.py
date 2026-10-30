"""Remediation commands: pasting a whole block must never break a running workload."""

import re
from datetime import datetime, timedelta, timezone

import pytest

from src.nhi_scanner.demo import build_demo_snapshot
from src.nhi_scanner.engine import run_scan

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
MICROSOFT = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"


def _cred(name, **extra):
    return {"keyId": f"key-{name}", "displayName": name, "startDateTime": "2026-01-01T00:00:00Z",
            "endDateTime": "2027-06-01T00:00:00Z", **extra}


@pytest.fixture(scope="module")
def payload():
    return run_scan(build_demo_snapshot(NOW), now=NOW)


def live(command):
    """The lines a shell would run."""
    return [line for line in command.splitlines() if not line.lstrip().startswith("#")]


def finding(payload, rule_id, name):
    return next(f for f in payload.findings if f.rule_id == rule_id and f.entity_name == name)


def test_only_expired_credentials_are_deleted_by_a_pasted_block(payload):
    for f in payload.findings:
        if f.rule_id != "NHI-SEC-001":
            assert not [line for line in live(f.remediation_cli) if "credential delete" in line], f.rule_id


def test_placeholders_cannot_become_shell_redirections(payload):
    for f in payload.findings:
        for line in live(f.remediation_cli):
            unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", "", line)
            assert "<" not in unquoted and ">" not in unquoted, line
            assert "$" not in unquoted, line


def test_every_rule_family_gets_commands(payload):
    assert all(f.remediation_cli.strip() for f in payload.findings)
    assert not any("federated-credential.json" in f.remediation_cli for f in payload.findings)


def test_multiple_secrets_never_deletes_the_one_in_use(payload):
    f = finding(payload, "NHI-SEC-003", "Identity Automation")
    lines = live(f.remediation_cli)
    assert len(lines) == 1 and lines[0].startswith("az ad app credential list")
    assert f.remediation_cli.count("# az ad app credential delete") == 3


def test_contributor_is_narrowed_before_the_broad_role_goes(payload):
    f = finding(payload, "NHI-RBAC-002", "ci-deploy-pipeline")
    lines = f.remediation_cli.splitlines()
    create = next(i for i, line in enumerate(lines) if "role assignment create" in line)
    delete = next(i for i, line in enumerate(lines) if "role assignment delete" in line)
    assert create < delete and lines[delete].startswith("# ")


def test_dormancy_disables_first_and_removes_credentials_later(payload):
    f = finding(payload, "NHI-DORM-001", "legacy-hr-sync")
    assert [line.split()[1:3] for line in live(f.remediation_cli)] == [["ad", "sp"]]
    assert "--set accountEnabled=false" in f.remediation_cli
    assert "# az ad app credential delete" in f.remediation_cli


def test_dormancy_never_targets_microsoft_managed_or_disabled_identities():
    snap = build_demo_snapshot(NOW)
    by_name = {sp["displayName"]: sp for sp in snap.service_principals}
    by_name["Office 365 Exchange Online"]["passwordCredentials"] = [_cred("ms")]
    by_name["id-aks-workload"]["keyCredentials"] = [_cred("mi", type="AsymmetricX509Cert")]
    snap.signin_activity = {k: v for k, v in snap.signin_activity.items()
                            if k not in (by_name["Office 365 Exchange Online"]["appId"],
                                         by_name["id-aks-workload"]["appId"])}
    by_name["legacy-hr-sync"]["accountEnabled"] = False
    p = run_scan(snap, now=NOW)
    dormant = {f.entity_name for f in p.findings if f.rule_id.startswith("NHI-DORM")}
    assert not dormant & {"Office 365 Exchange Online", "id-aks-workload", "legacy-hr-sync"}
    assert "marketing-analytics-poc" in dormant  # the enabled, unused app is still reported


def test_agent_id_orphan_gets_a_sponsor_not_an_owner(payload):
    f = finding(payload, "NHI-AGENT-001", "Sales Outreach Agent")
    assert "/microsoft.graph.agentIdentity/sponsors/$ref'" in f.remediation_cli
    assert "owner" not in f.remediation_cli.lower()
    assert "no owner or sponsor" in f.description


def test_service_principal_owner_url_is_quoted():
    snap = build_demo_snapshot(NOW)
    fin = next(a for a in snap.applications if a["displayName"] == "Finance Copilot Agent")
    snap.applications.remove(fin)
    sp = next(s for s in snap.service_principals if s["appId"] == fin["appId"])
    sp["appOwnerOrganizationId"] = snap.tenant_id  # tenant-owned, app object gone
    f = finding(run_scan(snap, now=NOW), "NHI-AGENT-001", "Finance Copilot Agent")
    assert "/owners/$ref' --body '" in f.remediation_cli


def test_agent_secret_on_the_service_principal_uses_the_service_principal_command():
    snap = build_demo_snapshot(NOW)
    sp = next(s for s in snap.service_principals if s["displayName"] == "Finance Copilot Agent")
    sp["passwordCredentials"] = [_cred("on-sp")]
    f = finding(run_scan(snap, now=NOW), "NHI-AGENT-004", "Finance Copilot Agent")
    assert f"# az ad sp credential delete --id {sp['id']} --key-id key-on-sp" in f.remediation_cli
    assert "# az ad app credential delete" in f.remediation_cli


def test_agent_from_another_tenant_is_not_offered_a_federated_credential():
    snap = build_demo_snapshot(NOW)
    snap.service_principals.append({
        "id": "vendor-sp", "appId": "vendor-app", "displayName": "Vendor Copilot", "servicePrincipalType": "Application",
        "accountEnabled": True, "appOwnerOrganizationId": "another-tenant", "tags": [], "alternativeNames": [],
        "passwordCredentials": [_cred("vendor")], "keyCredentials": [], "owners": [],
    })
    f = finding(run_scan(snap, now=NOW), "NHI-AGENT-004", "Vendor Copilot")
    assert "federated-credential" not in f.remediation_cli and "vendor" in f.remediation_cli


def test_expiring_certificates_are_rotated_as_certificates():
    snap = build_demo_snapshot(NOW)
    pay = next(a for a in snap.applications if a["displayName"] == "payments-api")
    pay["keyCredentials"][0]["endDateTime"] = (NOW + timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    f = finding(run_scan(snap, now=NOW), "NHI-SEC-005", "payments-api")
    assert '--cert "@<NEW_CERTIFICATE_FILE>"' in f.remediation_cli
    assert "--display-name rotated" not in f.remediation_cli


def test_a_new_secret_never_reaches_the_terminal(payload):
    f = finding(payload, "NHI-SEC-005", "marketing-analytics-poc")
    line = next(line for line in f.remediation_cli.splitlines() if "credential reset" in line)
    assert line.startswith("# az keyvault secret set") and " -o none " in line

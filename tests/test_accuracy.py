"""False alarms a first real scan would otherwise show on page one."""

from datetime import datetime, timezone

import pytest

from src.nhi_scanner.demo import build_demo_snapshot
from src.nhi_scanner.engine import run_scan
from src.nhi_scanner.inventory import agent_signals
from src.nhi_scanner.models import EntityType, Severity

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
MICROSOFT = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
EXCHANGE_APP = "00000002-0000-0ff1-ce00-000000000000"
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
APP_ADMIN = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"


def _cert(name="c"):
    return {"keyId": f"key-{name}", "displayName": name, "type": "AsymmetricX509Cert",
            "startDateTime": "2026-01-01T00:00:00Z", "endDateTime": "2027-06-01T00:00:00Z"}


def _sp(snap, name):
    return next(s for s in snap.service_principals if s["displayName"] == name)


def _findings(payload, rule_id):
    return {f.entity_name: f for f in payload.findings if f.rule_id == rule_id}


def test_managed_identity_platform_certificate_is_not_a_finding():
    snap = build_demo_snapshot(NOW)
    _sp(snap, "id-aks-workload")["keyCredentials"] = [_cert()]
    assert "id-aks-workload" not in _findings(run_scan(snap, now=NOW), "NHI-SEC-004")


def test_credentials_on_an_ordinary_service_principal_are_still_found():
    assert "sharepoint-migration-tool" in _findings(run_scan(build_demo_snapshot(NOW), now=NOW), "NHI-SEC-004")


def test_third_party_app_is_not_orphaned_but_a_tenant_app_without_its_registration_is():
    snap = build_demo_snapshot(NOW)
    app = next(a for a in snap.applications if a["displayName"] == "legacy-hr-sync")
    snap.applications.remove(app)  # its service principal stays, still owned by this tenant
    p = run_scan(snap, now=NOW)
    entities = {e.display_name: e for e in p.entities}
    assert not entities["Acme Cloud Backup"].is_orphaned
    assert entities["Acme Cloud Backup"].raw_metadata["is_external_app"] is True
    assert entities["legacy-hr-sync"].is_orphaned


def _with_role(template, scope):
    snap = build_demo_snapshot(NOW)
    sp = _sp(snap, "payments-api")
    snap.directory_role_definitions[template] = {"displayName": "role", "templateId": template}
    snap.directory_role_assignments.append({
        "id": "scoped", "principalId": sp["id"], "roleDefinitionId": template, "directoryScopeId": scope,
    })
    return run_scan(snap, now=NOW)


def test_role_limited_to_an_administrative_unit_is_not_a_takeover():
    f = _findings(_with_role(GLOBAL_ADMIN, "/administrativeUnits/au-1"), "NHI-PERM-003")["payments-api"]
    assert f.severity is Severity.MEDIUM
    assert "(scoped)" in f.title and "take over the entire tenant" not in f.attack_path_context


def test_role_limited_to_one_application_is_not_a_takeover():
    f = _findings(_with_role(APP_ADMIN, "/app-object-id"), "NHI-PERM-003")["payments-api"]
    assert f.severity is Severity.MEDIUM


def test_tenant_wide_role_stays_critical():
    f = _findings(_with_role(GLOBAL_ADMIN, "/"), "NHI-PERM-003")["payments-api"]
    assert f.severity is Severity.CRITICAL and "take over the entire tenant" in f.attack_path_context


def _hybrid_snapshot(app_id=EXCHANGE_APP, **creds):
    snap = build_demo_snapshot(NOW)
    sp = _sp(snap, "Office 365 Exchange Online")
    sp.update(appId=app_id, passwordCredentials=[], keyCredentials=[_cert()], **creds)
    return snap


def test_hybrid_certificate_is_a_check_not_a_solorigate_alarm():
    f = _findings(run_scan(_hybrid_snapshot(), now=NOW), "NHI-SEC-004")["Office 365 Exchange Online"]
    assert f.severity is Severity.MEDIUM
    assert "hybrid" in f.title.lower() and "Solorigate" not in f.description
    assert "# az ad sp credential delete" in f.remediation_cli


def test_secret_on_a_hybrid_app_stays_critical():
    snap = _hybrid_snapshot()
    _sp(snap, "Office 365 Exchange Online")["passwordCredentials"] = [_cert("secret")]
    f = _findings(run_scan(snap, now=NOW), "NHI-SEC-004")["Office 365 Exchange Online"]
    assert f.severity is Severity.CRITICAL


def test_certificate_on_any_other_microsoft_app_stays_critical():
    f = _findings(run_scan(_hybrid_snapshot(app_id="another-ms-app"), now=NOW), "NHI-SEC-004")
    assert f["Office 365 Exchange Online"].severity is Severity.CRITICAL


@pytest.mark.parametrize("name", [
    "Zabbix Agent", "Microsoft Monitoring Agent", "backup-agent", "Legal Assistant", "Scheduling Assistant",
    "Mail Bot", "Azure DevOps Bot", "robotics-sync", "bottle-service", "reagent-tracker", "MailAI", "payments-api",
])
def test_ordinary_software_is_not_an_ai_agent(name):
    assert agent_signals({"displayName": name}, None) == []


@pytest.mark.parametrize("name", [
    "Finance Copilot", "ChatGPT connector", "chatgpt-enterprise", "gpt4-summarizer", "GPT-4o reader", "Azure OpenAI gateway",
    "OpenAI", "Claude for Work", "anthropic-proxy", "langchain_worker", "crewai-runner", "mcp-server-graph",
    "SalesAIAgent", "ai_agent_runner", "foundry-research-agent", "HR AI Assistant", "support-chatbot",
    "LLM Router", "Copilots",
])
def test_real_ai_apps_are_recognised(name):
    assert agent_signals({"displayName": name}, None), name


def test_tags_still_classify_an_agent():
    assert agent_signals({"displayName": "plain name", "tags": ["AIAgent"]}, None) == ["tag:aiagent"]


def _with_owner(owner):
    snap = build_demo_snapshot(NOW)
    fin = next(a for a in snap.applications if a["displayName"] == "Finance Copilot Agent")
    fin["owners"] = [owner]
    return run_scan(snap, now=NOW)


def test_agent_owned_only_by_a_service_principal_has_nobody_accountable():
    p = _with_owner({"@odata.type": "#microsoft.graph.servicePrincipal", "id": "sp-owner"})
    agent = next(e for e in p.entities if e.display_name == "Finance Copilot Agent"
                 and e.entity_type is EntityType.AI_AGENT)
    assert agent.owners == [] and "Finance Copilot Agent" in _findings(p, "NHI-AGENT-001")


def test_agent_with_a_person_as_owner_is_accountable():
    p = _with_owner({"@odata.type": "#microsoft.graph.user", "id": "u1", "userPrincipalName": "a@demo-corp.example"})
    assert "Finance Copilot Agent" not in _findings(p, "NHI-AGENT-001")

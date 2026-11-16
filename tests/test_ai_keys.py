"""Azure OpenAI and AI Services accounts whose static keys still work: entities of type api_key and NHI-SEC-007."""

from datetime import datetime, timezone

import pytest

from src.nhi_scanner import collector
from src.nhi_scanner.demo import build_demo_snapshot
from src.nhi_scanner.engine import run_scan
from src.nhi_scanner.models import EntityType, SectionStatus, Severity

from test_collector import _backend

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def demo():
    return run_scan(build_demo_snapshot(NOW), now=NOW)


def finding(payload, account):
    return next((f for f in payload.findings if f.rule_id == "NHI-SEC-007" and f.entity_name == f"{account} (keys)"), None)


def test_open_keys_on_a_public_account_are_high_and_name_who_can_read_them(demo):
    f = finding(demo, "oai-finance-copilot")
    assert f.severity is Severity.HIGH and "from the internet" in f.title
    readers = {(r["identity"], r["role"]) for r in f.evidence["key_readers"]}
    # the role on the account itself, on its subscription, and on the subscription again: all reach the keys
    assert readers == {("Finance Copilot Agent", "Cognitive Services User"), ("ci-deploy-pipeline", "Contributor"),
                       ("func-invoice-processor", "Owner")}
    assert "Finance Copilot Agent" in f.attack_path_context


def test_restricted_network_is_medium_and_disabled_keys_raise_nothing(demo):
    assert finding(demo, "ais-research").severity is Severity.MEDIUM
    assert finding(demo, "oai-helpdesk") is None
    # a role on another resource group does not reach the keys
    assert "payments-api" not in {r["identity"] for r in finding(demo, "ais-research").evidence["key_readers"]}


def test_keys_are_entities_with_their_own_record(demo):
    keys = {e.display_name: e for e in demo.entities if e.entity_type is EntityType.API_KEY}
    assert set(keys) == {"oai-finance-copilot (keys)", "ais-research (keys)", "oai-helpdesk (keys)"}
    live = keys["oai-finance-copilot (keys)"]
    assert not live.is_orphaned  # an Azure resource has no owner field: not orphaned by omission
    assert [c.display_name for c in live.record.credentials.items] == ["key1", "key2"]
    assert all(c.kind.value == "api_key" and c.held_on == "resource" for c in live.record.credentials.items)
    assert live.record.owners.status is SectionStatus.NOT_APPLICABLE
    off = keys["oai-helpdesk (keys)"]
    assert off.record.credentials.items == [] and "disabled" in off.record.credentials.note
    assert demo.metadata.summary_counts.by_entity_type.api_key == 3


def test_remediation_is_held_and_turns_keys_off(demo):
    cli = finding(demo, "oai-finance-copilot").remediation_cli
    live = [line for line in cli.splitlines() if not line.startswith("#")]
    assert live == [] and "--set properties.disableLocalAuth=true" in cli


def test_other_rules_ignore_key_entities(demo):
    keys = {e.entity_id for e in demo.entities if e.entity_type is EntityType.API_KEY}
    assert {f.rule_id for f in demo.findings if f.entity_id in keys} == {"NHI-SEC-007"}


def test_azure_not_read_skips_the_rule():
    snap = build_demo_snapshot(NOW)
    snap.ai_accounts = None
    p = run_scan(snap, now=NOW)
    assert "NHI-SEC-007" not in p.metadata.rules_evaluated
    assert not [e for e in p.entities if e.entity_type is EntityType.API_KEY]


SUB = "sub-1"
ACCOUNTS = f"/subscriptions/{SUB}/providers/Microsoft.CognitiveServices/accounts"
ROUTES = {
    "/subscriptions": {"value": [{"subscriptionId": SUB}]},
    f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions": {"value": []},
    f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments": {"value": []},
    f"/subscriptions/{SUB}/providers/Microsoft.ManagedIdentity/userAssignedIdentities": {"value": []},
    ACCOUNTS: {"value": [
        {"id": f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/oai-1",
         "name": "oai-1", "kind": "OpenAI", "location": "swedencentral", "sku": {"name": "S0"},
         "properties": {"endpoint": "https://oai-1.openai.azure.com/", "publicNetworkAccess": "Enabled"}},
        {"id": f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/face-1",
         "name": "face-1", "kind": "Face", "properties": {}},
    ]},
}


def test_collector_keeps_ai_kinds_and_reads_missing_flag_as_keys_on(monkeypatch):
    _backend(monkeypatch, routes=ROUTES)
    snap = collector.collect()
    [acc] = snap.ai_accounts  # Face is not an AI model account
    assert (acc["name"], acc["disable_local_auth"], acc["public_network_access"], acc["network_default_action"]) == (
        "oai-1", False, "Enabled", None)
    assert collector.SRC_AI_ACCOUNTS in snap.read_at
    assert finding(run_scan(snap), "oai-1").severity is Severity.HIGH


def test_unreadable_ai_accounts_are_a_warning(monkeypatch):
    _backend(monkeypatch, routes=ROUTES, forbidden=("Microsoft.CognitiveServices",))
    snap = collector.collect()
    assert snap.ai_accounts is None
    assert any("Azure OpenAI and AI Services accounts not read" in w for w in snap.warnings)

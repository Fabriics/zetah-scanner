import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from src.nhi_scanner.demo import DEMO_TENANT_ID, build_demo_snapshot
from src.nhi_scanner.engine import hygiene_score, run_scan
from src.nhi_scanner.models import (
    EntityType,
    NHIEntity,
    Severity,
    ZetahScanPayload,
    compute_finding_id,
)

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def payload() -> ZetahScanPayload:
    return run_scan(build_demo_snapshot(NOW), now=NOW)


def rules_for(payload, name):
    return {f.rule_id for f in payload.findings if f.entity_name == name}


def test_demo_payload_round_trips_through_json(payload):
    raw = payload.model_dump_json()
    again = ZetahScanPayload.model_validate_json(raw)
    assert again == payload
    data = json.loads(raw)
    assert set(data) == {"metadata", "entities", "findings"}
    assert data["metadata"]["tenant_id"] == DEMO_TENANT_ID
    assert data["metadata"]["scanner_version"] == "0.1.0"
    assert data["metadata"]["scan_timestamp"] == "2026-10-26T12:00:00Z"


def test_finding_ids_are_deterministic_across_scans(payload):
    other = run_scan(build_demo_snapshot(NOW), now=NOW)
    assert other.metadata.scan_id != payload.metadata.scan_id
    assert [f.finding_id for f in other.findings] == [f.finding_id for f in payload.findings]
    f = payload.findings[0]
    assert f.finding_id == compute_finding_id(DEMO_TENANT_ID, f.entity_id, f.rule_id)


def test_every_category_and_rule_family_is_exercised(payload):
    assert {f.category.value for f in payload.findings} == {
        "secret_hygiene", "dormant_nhi", "excessive_graph_permissions", "azure_rbac_privilege", "ai_agent_governance",
    }
    assert set(payload.metadata.rules_evaluated) == {f.rule_id for f in payload.findings}


def test_expected_detections(payload):
    assert rules_for(payload, "Finance Copilot Agent") >= {
        "NHI-AGENT-001", "NHI-AGENT-002", "NHI-AGENT-003", "NHI-AGENT-004", "NHI-AGENT-005", "NHI-PERM-002",
    }
    assert rules_for(payload, "legacy-hr-sync") >= {"NHI-SEC-001", "NHI-DORM-001", "NHI-PERM-001", "NHI-PERM-003"}
    assert "NHI-RBAC-001" in rules_for(payload, "func-invoice-processor")
    assert "NHI-DORM-002" in rules_for(payload, "marketing-analytics-poc")
    assert rules_for(payload, "payments-api") == set()
    assert rules_for(payload, "id-aks-workload") == set()


def test_first_party_backdoor_is_critical_and_untouched_first_party_is_ignored(payload):
    exo = [f for f in payload.findings if f.entity_name == "Office 365 Exchange Online"]
    assert [(f.rule_id, f.severity) for f in exo] == [("NHI-SEC-004", Severity.CRITICAL)]
    assert all(e.display_name != "Microsoft Graph" for e in payload.entities)


def test_orphan_semantics(payload):
    by_name = {(e.display_name, e.entity_type): e for e in payload.entities}
    assert by_name[("legacy-hr-sync", EntityType.SERVICE_PRINCIPAL)].is_orphaned
    # ownerless by design: managed identities (incl. MI-backed agents), Microsoft first-party SPs, third-party apps
    assert not by_name[("Acme Cloud Backup", EntityType.SERVICE_PRINCIPAL)].is_orphaned
    assert not by_name[("func-invoice-processor", EntityType.MANAGED_IDENTITY)].is_orphaned
    assert not by_name[("id-foundry-research-agent", EntityType.AI_AGENT)].is_orphaned
    assert not by_name[("Office 365 Exchange Online", EntityType.SERVICE_PRINCIPAL)].is_orphaned
    assert "NHI-AGENT-001" not in rules_for(payload, "id-foundry-research-agent")


def test_is_orphaned_cannot_be_spoofed():
    e = NHIEntity(entity_id="x", display_name="x", entity_type="service_principal", owners=[], is_orphaned=False)
    assert e.is_orphaned is True


def test_dormancy_rules_skipped_without_signin_data():
    snap = build_demo_snapshot(NOW)
    snap.signin_activity = None
    p = run_scan(snap, now=NOW)
    assert not any(r.startswith("NHI-DORM") for r in p.metadata.rules_evaluated)
    assert not any(f.rule_id.startswith("NHI-DORM") for f in p.findings)


def test_rbac_rules_skipped_without_azure_data():
    snap = build_demo_snapshot(NOW)
    snap.azure_role_assignments = None
    p = run_scan(snap, now=NOW)
    assert not any(r.startswith("NHI-RBAC") for r in p.metadata.rules_evaluated)


@pytest.mark.parametrize("mutate, message", [
    (lambda d: d["findings"][0].update(finding_id="0" * 64), "finding_id mismatch"),
    (lambda d: d["findings"][0].update(entity_id="ghost"), "unknown entity"),
    (lambda d: d["findings"].append(dict(d["findings"][0])), "summary_counts|duplicate"),
    (lambda d: d["metadata"]["summary_counts"]["by_severity"].update(critical=0), "summary_counts"),
    (lambda d: d["findings"][0].update(severity="SEVERE"), "severity"),
    (lambda d: d["entities"][0].update(entity_type="robot"), "entity_type"),
    (lambda d: d["metadata"].update(hygiene_score=101), "hygiene_score"),
    (lambda d: d["metadata"].update(scan_timestamp="2026-10-26T12:00:00"), "timezone"),
    (lambda d: d["findings"][0].update(rule_id="SEC-1"), "rule_id"),
    (lambda d: d.update(extra_field=1), "extra"),
])
def test_contract_rejects_bad_payloads(payload, mutate, message):
    data = json.loads(payload.model_dump_json())
    mutate(data)
    with pytest.raises(ValidationError, match=f"(?i){message}"):
        ZetahScanPayload.model_validate(data)


def test_hygiene_score_rises_as_findings_are_fixed(payload):
    findings = list(payload.findings)
    scores = []
    while findings:
        scores.append(hygiene_score(findings))
        findings.pop(0)  # sorted by severity: fix the worst first
    scores.append(hygiene_score([]))
    assert scores == sorted(scores) and scores[-1] == 100
    # at demo-tenant scale there are no long plateaus: never 4 identical scores in a row
    assert all(len(set(scores[i:i + 4])) > 1 for i in range(len(scores) - 3))
    assert 0 <= payload.metadata.hygiene_score <= 74
    without_criticals = hygiene_score([f for f in payload.findings if f.severity is not Severity.CRITICAL])
    assert without_criticals >= payload.metadata.hygiene_score + 30


def test_dormancy_ignores_identities_whose_signins_are_not_observable():
    snap = build_demo_snapshot(NOW)
    poc = next(a for a in snap.applications if a["displayName"] == "marketing-analytics-poc")
    poc["signInAudience"] = "AzureADandPersonalMicrosoftAccount"
    snap.service_principals = [sp for sp in snap.service_principals if sp["displayName"] != "payments-api"]
    p = run_scan(snap, now=NOW)
    assert "NHI-DORM-002" not in rules_for(p, "marketing-analytics-poc")
    payments_app = next(e for e in p.entities if e.display_name == "payments-api")
    assert payments_app.is_enabled and payments_app.raw_metadata["service_principal_id"] is None
    assert rules_for(p, "payments-api") == set()


def test_large_tenants_plateau_and_the_report_says_so(tmp_path):
    """With many findings of one severity a fix can move the integer score by less than a point."""
    from types import SimpleNamespace

    from src.nhi_scanner.pdf_report import write_pdf_report
    from pypdf import PdfReader

    highs = [SimpleNamespace(severity=Severity.HIGH) for _ in range(40)]
    scores = [hygiene_score(highs[i:]) for i in range(len(highs) + 1)]
    assert scores == sorted(scores) and scores[-1] == 100  # never drops, always ends at 100
    assert any(len(set(scores[i:i + 4])) == 1 for i in range(len(scores) - 3))  # but it does plateau
    assert scores[-1] - scores[0] >= 20  # and fixing all of them is clearly visible

    out = write_pdf_report(run_scan(build_demo_snapshot(NOW), now=NOW), tmp_path / "r.pdf")
    text = " ".join(" ".join(p.extract_text() for p in PdfReader(str(out)).pages).split())
    assert "several fixes may be needed before it moves by one point" in text
    assert "keeps moving" not in text


def test_score_bands_match_how_a_ciso_reads_them():
    from types import SimpleNamespace

    def score(**counts):
        return hygiene_score([SimpleNamespace(severity=Severity[sev.upper()]) for sev, n in counts.items() for _ in range(n)])

    assert score() == 100
    assert score(high=1) >= 90  # one issue is not a crisis
    assert score(high=5) < 80  # a handful of high findings is never "Good"
    assert score(high=80) < 50  # many of them is "At risk"
    assert score(critical=1) == 74  # any takeover path keeps the tenant out of "Good"
    assert score(low=30) >= 90 and score(medium=10) >= 80  # hygiene noise does not dominate
    assert score(critical=3, high=10) < score(high=10) < score(high=5)

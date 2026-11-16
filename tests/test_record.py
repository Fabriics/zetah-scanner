"""The identity record: every identity described in full, with where each part comes from."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.nhi_scanner.demo import build_demo_snapshot
from src.nhi_scanner.engine import run_scan
from src.nhi_scanner.models import (
    CONTRACT_VERSION,
    EntityType,
    GraphPermissionsSection,
    SectionStatus,
    ZetahScanPayload,
)
from src.nhi_scanner.snapshot import SRC_APPLICATIONS, SRC_GRAPH_PERMISSIONS, SRC_SERVICE_PRINCIPALS

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
V1_PAYLOAD = Path(__file__).parent / "fixtures" / "payload_contract_v1.json"


@pytest.fixture(scope="module")
def payload() -> ZetahScanPayload:
    return run_scan(build_demo_snapshot(NOW), now=NOW)


def entity(payload, name, etype=None):
    return next(e for e in payload.entities
                if e.display_name == name and (etype is None or e.entity_type is etype))


def test_every_identity_has_a_record(payload):
    assert payload.metadata.contract_version == CONTRACT_VERSION == 2
    assert all(e.record is not None for e in payload.entities)


def test_a_clean_identity_shows_what_it_can_do_and_with_which_keys(payload):
    """The 0.1 gap: an identity without findings showed neither its permissions nor its credentials."""
    sp = entity(payload, "payments-api", EntityType.SERVICE_PRINCIPAL)
    assert not [f for f in payload.findings if f.entity_id == sp.entity_id]
    r = sp.record
    assert [p.permission for p in r.graph_permissions.items] == ["User.Read.All"]
    assert [x.role for x in r.directory_roles.items] == ["Directory Readers"]
    assert [(a.role, a.scope.rsplit("/", 1)[-1]) for a in r.azure_roles.items] == [("Contributor", "rg-payments")]
    [cred] = r.credentials.items
    assert (cred.kind.value, cred.display_name, cred.held_on) == ("certificate", "payments-2026", "application")
    assert cred.end is not None


def test_every_section_says_where_it_comes_from_and_when(payload):
    for e in payload.entities:
        for name, section in e.record:
            if section.status is SectionStatus.READ:
                assert section.sources and section.read_at == NOW, (e.display_name, name)
    sp = entity(payload, "payments-api", EntityType.SERVICE_PRINCIPAL)
    assert sp.record.credentials.sources == [SRC_SERVICE_PRINCIPALS, SRC_APPLICATIONS]
    assert sp.record.graph_permissions.sources == [SRC_GRAPH_PERMISSIONS]


def test_service_principal_record_merges_both_objects_and_marks_where_each_part_lives(payload):
    spmig = entity(payload, "sharepoint-migration-tool", EntityType.SERVICE_PRINCIPAL)
    assert {c.held_on for c in spmig.record.credentials.items} == {"service_principal"}
    assert {o.held_on for o in spmig.record.owners.items} == {"application"}
    app = entity(payload, "sharepoint-migration-tool", EntityType.APP_REGISTRATION)
    assert app.record.graph_permissions.status is SectionStatus.NOT_APPLICABLE
    assert "service principal" in app.record.graph_permissions.note


def test_owner_account_status_is_part_of_the_record(payload):
    [owner] = entity(payload, "marketing-analytics-poc", EntityType.APP_REGISTRATION).record.owners.items
    assert (owner.user_principal_name, owner.object_type.value, owner.account_enabled) == (
        "growth@demo-corp.example", "user", False)
    [owner] = entity(payload, "payments-api", EntityType.APP_REGISTRATION).record.owners.items
    assert owner.account_enabled is True


def test_sponsors_only_exist_for_agent_id_identities(payload):
    agents = [e for e in payload.entities if e.raw_metadata.get("agent_identity_blueprint_id") is not None
              or "entra_agent_id" in e.raw_metadata.get("agent_classification_signals", [])]
    assert agents
    for e in agents:
        assert e.record.sponsors.status is SectionStatus.READ
    assert entity(payload, "payments-api", EntityType.SERVICE_PRINCIPAL).record.sponsors.status \
        is SectionStatus.NOT_APPLICABLE


def test_by_design_gaps_are_explained(payload):
    mi = entity(payload, "func-invoice-processor", EntityType.MANAGED_IDENTITY)
    assert "managed identity" in mi.record.owners.note.lower()
    assert "never listed" in mi.record.credentials.note
    ext = entity(payload, "Acme Cloud Backup")
    assert "another organization" in ext.record.owners.note
    assert "not visible" in ext.record.credentials.note


@pytest.mark.parametrize("field, section", [
    ("signin_activity", "activity"),
    ("graph_app_role_assignments", "graph_permissions"),
    ("directory_role_assignments", "directory_roles"),
    ("azure_role_assignments", "azure_roles"),
])
def test_not_read_is_not_empty(field, section):
    snap = build_demo_snapshot(NOW)
    setattr(snap, field, None)
    p = run_scan(snap, now=NOW)
    for e in p.entities:
        s = getattr(e.record, section)
        if s.status is SectionStatus.NOT_APPLICABLE:
            continue
        assert s.status is SectionStatus.NOT_READ and s.note and not s.sources, (e.display_name, section)


def test_unreadable_sponsors_are_not_read_not_absent():
    snap = build_demo_snapshot(NOW)
    for sp in snap.service_principals:
        sp.pop("sponsors", None)
    p = run_scan(snap, now=NOW)
    agent_ids = [e for e in p.entities if e.raw_metadata.get("sponsors_unknown")]
    assert agent_ids and all(e.record.sponsors.status is SectionStatus.NOT_READ for e in agent_ids)


def test_activity_tells_never_signed_in_from_not_read(payload):
    hr = entity(payload, "legacy-hr-sync", EntityType.SERVICE_PRINCIPAL).record.activity
    assert hr.status is SectionStatus.READ
    snap = build_demo_snapshot(NOW)
    snap.signin_activity = None
    hr2 = entity(run_scan(snap, now=NOW), "legacy-hr-sync", EntityType.SERVICE_PRINCIPAL).record.activity
    assert hr2.status is SectionStatus.NOT_READ and hr2.last_sign_in is None


def test_read_times_come_from_the_reads_themselves():
    snap = build_demo_snapshot(NOW)
    earlier = NOW - timedelta(minutes=3)
    snap.read_at = {SRC_APPLICATIONS: earlier, SRC_GRAPH_PERMISSIONS: NOW - timedelta(minutes=1)}
    sp = entity(run_scan(snap, now=NOW), "payments-api", EntityType.SERVICE_PRINCIPAL).record
    assert sp.credentials.read_at == earlier  # the oldest of its sources
    assert sp.graph_permissions.read_at == NOW - timedelta(minutes=1)


def test_secret_values_and_hints_never_reach_the_record(payload):
    raw = json.dumps([json.loads(e.record.model_dump_json()) for e in payload.entities])
    assert '"hint"' not in raw and "secretText" not in raw


def test_section_status_must_match_its_content():
    with pytest.raises(ValidationError, match="holds data"):
        GraphPermissionsSection(status="not_read", items=[{"permission": "Mail.Read", "assignment_id": "a"}])
    with pytest.raises(ValidationError, match="sources and read_at"):
        GraphPermissionsSection(status="read", items=[])
    GraphPermissionsSection(status="not_read", note="could not be read")


# --------------------------------------------------------------------------- #
# Contract versions
# --------------------------------------------------------------------------- #

def test_payloads_written_by_scanner_0_1_still_validate():
    data = json.loads(V1_PAYLOAD.read_text(encoding="utf-8"))
    assert data["metadata"]["scanner_version"] == "0.1.1" and "contract_version" not in data["metadata"]
    old = ZetahScanPayload.model_validate(data)
    assert old.metadata.contract_version == 1
    assert all(e.record is None for e in old.entities)


def test_contract_versions_cannot_be_mixed(payload):
    data = json.loads(payload.model_dump_json())
    data["entities"][0]["record"] = None
    with pytest.raises(ValidationError, match="record on every entity"):
        ZetahScanPayload.model_validate(data)

    data = json.loads(V1_PAYLOAD.read_text(encoding="utf-8"))
    data["entities"][0]["record"] = json.loads(payload.entities[0].record.model_dump_json())
    with pytest.raises(ValidationError, match="carry no identity record"):
        ZetahScanPayload.model_validate(data)


def test_record_rejects_unknown_fields(payload):
    data = json.loads(payload.model_dump_json())
    data["entities"][0]["record"]["profile"]["guess"] = "x"
    with pytest.raises(ValidationError, match="(?i)extra"):
        ZetahScanPayload.model_validate(data)

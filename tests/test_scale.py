"""Scale (T-14): the generated large tenant, the collector reading it through a simulated Graph, and the reports."""

import dataclasses
import json
from datetime import datetime, timezone

import pytest

from fake_graph import FakeGraph, install
from src.nhi_scanner import collector
from src.nhi_scanner.cli import MAX_DEMO_SIZE, main
from src.nhi_scanner.demo import build_scale_snapshot
from src.nhi_scanner.engine import run_scan, write_payload_json
from src.nhi_scanner.inventory import build_inventory

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=timezone.utc)
SIZE = 3000


@pytest.fixture(scope="module")
def tenant():
    return build_scale_snapshot(SIZE, now=NOW)


def _without_azure(snap):
    """The collector is run without Azure here: compare against the same tenant without its Azure part."""
    return dataclasses.replace(snap, azure_role_assignments=None, mi_federated_credentials=None, ai_accounts=None)


def _findings(snap):
    return {(f.rule_id, f.entity_id) for f in run_scan(snap, now=NOW).findings}


def _collect(monkeypatch, graph):
    install(monkeypatch, graph)
    return collector.collect(include_azure_rbac=False)


def test_generator_reaches_the_requested_size_the_same_way_every_time(tenant):
    entities = build_inventory(tenant).entities
    assert abs(len(entities) - SIZE) <= SIZE * 0.01
    again = build_scale_snapshot(SIZE, now=NOW)
    assert [sp["id"] for sp in again.service_principals] == [sp["id"] for sp in tenant.service_principals]
    kinds = {e.entity_type.value for e in entities}
    assert {"app_registration", "service_principal", "managed_identity", "ai_agent"} <= kinds


def test_every_rule_family_has_something_to_find_at_scale(tenant):
    from src.nhi_scanner.demo import build_demo_snapshot

    demo = {sp["id"] for sp in build_demo_snapshot(NOW).service_principals} | {
        a["id"] for a in build_demo_snapshot(NOW).applications}
    rules = {r for r, entity in _findings(tenant) if entity not in demo}  # only what the generator added
    for family in ("NHI-SEC", "NHI-PERM", "NHI-DORM", "NHI-AGENT", "NHI-RBAC"):
        assert any(r.startswith(family) for r in rules), family


def test_collector_reads_back_exactly_the_generated_tenant(monkeypatch, tenant):
    graph = FakeGraph(tenant)
    snap = _collect(monkeypatch, graph)
    assert _findings(snap) == _findings(_without_azure(tenant))
    assert not [w for w in snap.warnings if "not read" in w]
    # federated credentials come from one expanded listing, not one read per app
    assert graph.stats.by_kind.get("federated credentials, one app", 0) == 0
    # pages of 999 where Graph allows them (100 with $expand): fewer pages than with Graph's default size
    pages = graph.stats.by_kind["listing page"]
    default = FakeGraph(tenant, top_supported=False)
    _collect(monkeypatch, default)
    assert pages < default.stats.by_kind["listing page"]


def test_without_the_expanded_listing_the_reads_one_by_one_give_the_same_answer(monkeypatch, tenant):
    graph = FakeGraph(tenant, expand_federation=False)
    snap = _collect(monkeypatch, graph)
    assert graph.stats.by_kind["federated credentials, one app"] == len(tenant.applications)
    assert snap.app_federated_credentials == tenant.app_federated_credentials


def test_a_graph_that_refuses_top_still_reads_everything(monkeypatch, tenant):
    graph = FakeGraph(tenant, top_supported=False)
    snap = _collect(monkeypatch, graph)
    assert _findings(snap) == _findings(_without_azure(tenant))
    assert graph.stats.by_kind["listing page"] > 60  # Graph's default pages of 100 everywhere


def test_throttled_requests_are_retried_until_the_read_is_complete(monkeypatch):
    small = build_scale_snapshot(400, now=NOW)
    graph = FakeGraph(small, ru_per_10s=200, burst=5)  # an almost empty bucket: the scan has to wait for it
    snap = _collect(monkeypatch, graph)
    assert graph.stats.throttled > 0
    assert _findings(snap) == _findings(_without_azure(small))


def test_a_paging_link_to_another_host_stops_the_parallel_reads(monkeypatch, tenant):
    graph = FakeGraph(tenant, expand_federation=False)
    sent_to = []
    real = graph._route

    def hostile(path, query):
        if path.endswith("/federatedIdentityCredentials"):
            return 200, {"value": [], "@odata.nextLink": "https://attacker.example/steal"}
        return real(path, query)

    graph._route = hostile
    real_get = graph.get

    def spy(session, url, params=None, **kwargs):
        sent_to.append(url)
        return real_get(url, params, **kwargs)

    install(monkeypatch, graph)
    monkeypatch.setattr("requests.Session.get", spy)
    snap = collector.collect(include_azure_rbac=False)
    assert snap.app_federated_credentials is None
    assert any("refusing to send the token" in w for w in snap.warnings)
    assert not [u for u in sent_to if "attacker" in u]
    # the first failure stops the reads not yet started
    assert sum(u.endswith("/federatedIdentityCredentials") for u in sent_to) < len(tenant.applications)


def test_sponsors_failing_halfway_are_dropped_for_every_agent(monkeypatch, tenant):
    graph = FakeGraph(tenant)
    agents = [a for a in tenant.service_principals if a.get("@odata.type", "").endswith("agentIdentity")]
    broken = agents[len(agents) // 2]["id"]
    real = graph._route

    def flaky(path, query):
        if path == f"/v1.0/servicePrincipals/{broken}/microsoft.graph.agentIdentity/sponsors":
            return 403, {"error": {"code": "Authorization_RequestDenied"}}
        return real(path, query)

    graph._route = flaky
    snap = _collect(monkeypatch, graph)
    assert any("Sponsors of Entra Agent ID identities not readable" in w for w in snap.warnings)
    collected = [sp for sp in snap.service_principals if sp.get("@odata.type", "").endswith("agentIdentity")]
    assert collected and not any("sponsors" in a for a in collected)


def test_streamed_json_is_the_same_bytes_as_the_whole_dump(tmp_path, tenant):
    payload = run_scan(tenant, now=NOW)
    out = tmp_path / "scan.json"
    write_payload_json(payload, out)
    assert out.read_text(encoding="utf-8") == payload.model_dump_json(indent=2) + "\n"
    empty = payload.model_copy(update={"entities": [], "findings": []})
    write_payload_json(empty, out)
    assert out.read_text(encoding="utf-8") == empty.model_dump_json(indent=2) + "\n"
    json.loads(out.read_text(encoding="utf-8"))


def test_large_reports_list_the_most_important_rows_and_count_the_rest(tmp_path, tenant):
    from pypdf import PdfReader

    from src.nhi_scanner.pdf_report import DETAILED_FINDINGS, PLAN_ROWS, write_pdf_report

    payload = run_scan(tenant, now=NOW)
    assert len(payload.findings) > PLAN_ROWS
    reader = PdfReader(str(write_pdf_report(payload, tmp_path / "r.pdf")))
    text = " ".join(" ".join(p.extract_text() for p in reader.pages).split())
    assert "Findings by rule" in text
    assert f"{len(payload.findings) - PLAN_ROWS} more findings are not listed here" in text
    assert f"{len(payload.findings) - DETAILED_FINDINGS} more findings are not listed here" in text
    assert f"most exposed of the {len(payload.entities)} identities" in text
    assert len(reader.pages) < 200


@pytest.mark.parametrize("argv", [["--demo-size", "100"], ["--demo", "--demo-size", "0"],
                                  ["--demo", "--demo-size", str(MAX_DEMO_SIZE + 1)]])
def test_demo_size_is_checked(argv, tmp_path):
    assert main([*argv, "--quiet", "--json", str(tmp_path / "s.json")]) == 1
    assert not (tmp_path / "s.json").exists()


def test_demo_size_scans_a_large_tenant_from_the_command_line(tmp_path):
    assert main(["--demo", "--demo-size", "1500", "--quiet", "--json", str(tmp_path / "s.json")]) == 0
    assert len(json.loads((tmp_path / "s.json").read_text(encoding="utf-8"))["entities"]) >= 1480

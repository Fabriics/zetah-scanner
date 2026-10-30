"""Entra Agent ID readiness, computed from the scan payload."""

from datetime import datetime, timezone

from pypdf import PdfReader

from src.nhi_scanner.demo import build_demo_snapshot
from src.nhi_scanner.engine import run_scan
from src.nhi_scanner.pdf_report import write_pdf_report
from src.nhi_scanner.readiness import agent_readiness
from src.nhi_scanner.snapshot import AGENT_ID_UNREADABLE

NOW = datetime(2026, 10, 26, 12, tzinfo=timezone.utc)


def test_demo_tenant_readiness():
    r = agent_readiness(run_scan(build_demo_snapshot(NOW), now=NOW))
    assert len(r.agents) == 5
    assert (r.count("agent_id"), r.count("legacy")) == (2, 3)
    assert (r.accountable, r.unaccountable, r.unknown) == (2, 3, 0)
    first = r.govern_first()
    assert [a.kind for a in first] == ["legacy"] * len(first)
    assert first[0].entity.display_name == "Finance Copilot Agent"  # critical and the most findings
    assert [a.risk for a in first] == sorted((a.risk for a in first), reverse=True)


def test_unreadable_sponsors_are_unknown():
    snap = build_demo_snapshot(NOW)
    for sp in snap.service_principals:
        sp.pop("sponsors", None)  # as when the sponsors call is forbidden
    r = agent_readiness(run_scan(snap, now=NOW))
    assert r.unknown == 2 and all(a.accountable is None for a in r.agents if a.kind == "agent_id")


def test_owner_known_stays_accountable_when_sponsors_are_unreadable():
    snap = build_demo_snapshot(NOW)
    agent = next(sp for sp in snap.service_principals if sp["displayName"] == "Procurement Agent")
    agent.pop("sponsors")
    agent["owners"] = [{"id": "u1", "userPrincipalName": "owner@demo-corp.example"}]
    r = agent_readiness(run_scan(snap, now=NOW))
    row = next(a for a in r.agents if a.entity.display_name == "Procurement Agent")
    assert row.accountable is True


def test_unreadable_agent_id_is_unknown_not_zero(tmp_path):
    snap = build_demo_snapshot(NOW)
    snap.service_principals = [sp for sp in snap.service_principals if "sponsors" not in sp]
    snap.warnings = [f"{AGENT_ID_UNREADABLE} (needs AgentIdentity.Read.All); agents may be missing. [403]"]
    payload = run_scan(snap, now=NOW)
    r = agent_readiness(payload)
    assert r.agent_id_readable is False and r.count("agent_id") == 0

    reader = PdfReader(str(write_pdf_report(payload, tmp_path / "r.pdf")))
    text = " ".join(" ".join(page.extract_text() for page in reader.pages).split())
    assert "Unknown" in text and "could not be read in this scan" in text
    assert "None yet" not in text


def test_agent_id_readable_on_a_normal_scan():
    assert agent_readiness(run_scan(build_demo_snapshot(NOW), now=NOW)).agent_id_readable is True

from datetime import datetime, timezone
from pathlib import Path

import pytest
from azure.core.exceptions import ClientAuthenticationError
from pypdf import PdfReader
from rich.console import Console

from src.nhi_scanner.cli import main
from src.nhi_scanner.demo import build_demo_snapshot
from src.nhi_scanner.engine import run_scan
from src.nhi_scanner.pdf_report import write_pdf_report
from src.nhi_scanner.report import render

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)


def pdf_text(path) -> tuple[PdfReader, str]:
    reader = PdfReader(str(path))
    return reader, "\n".join(page.extract_text() for page in reader.pages)


@pytest.fixture(scope="module")
def demo_payload():
    return run_scan(build_demo_snapshot(NOW), now=NOW)


def test_demo_report_contains_every_section_and_finding(demo_payload, tmp_path):
    out = write_pdf_report(demo_payload, tmp_path / "r.pdf", "Demo Corp")
    reader, text = pdf_text(out)
    assert out.read_bytes().startswith(b"%PDF")
    for section in ("Executive summary", "Risk overview", "Remediation plan", "Detailed findings",
                    "Non-human identity inventory", "Methodology & coverage"):
        assert section in text
    assert [o.title for o in reader.outline if hasattr(o, "title")][:3] == [
        "Executive summary", "Entra Agent ID readiness", "Risk overview"]
    for f in demo_payload.findings:
        assert f.rule_id in text
    for e in demo_payload.entities:
        assert e.display_name in text
    assert f"Page {len(reader.pages)} of {len(reader.pages)}" in text
    assert "28/100" in text or f"{demo_payload.metadata.hygiene_score}/100" in text
    assert reader.metadata.title == "NHI Security Assessment - Demo Corp"


def test_clean_tenant_and_missing_data_render(tmp_path):
    snap = build_demo_snapshot(NOW)
    snap.applications, snap.graph_app_role_assignments, snap.directory_role_assignments = [], [], []
    snap.service_principals = [sp for sp in snap.service_principals if sp["servicePrincipalType"] == "ManagedIdentity"]
    snap.signin_activity = None
    snap.azure_role_assignments = None
    snap.warnings = ["Sign-in activity unavailable (needs AuditLog.Read.All and Entra ID P1)"]
    payload = run_scan(snap, now=NOW)
    assert payload.findings == []
    _, text = pdf_text(write_pdf_report(payload, tmp_path / "clean.pdf"))
    text = " ".join(text.split())  # narrow table columns wrap labels across lines
    assert "No findings were raised" in text
    assert "Skipped: sign-in activity not available" in text
    assert "Skipped: Azure RBAC not scanned" in text
    assert "Coverage note" in text


def test_unicode_and_markup_in_names_do_not_break_rendering(demo_payload, tmp_path):
    p = demo_payload.model_copy(deep=True)
    p.entities[0].display_name = "Agent <b>evil</b> & 日本語 → ✓"
    _, text = pdf_text(write_pdf_report(p, tmp_path / "u.pdf", "Société Générale <Test>"))
    assert "Agent <b>evil</b> &" in text
    assert "Société Générale <Test>" in text


def test_bookmarks_open_the_right_page(demo_payload, tmp_path):
    reader, _ = pdf_text(write_pdf_report(demo_payload, tmp_path / "r.pdf"))

    def flat(items):
        for item in items:
            if isinstance(item, list):
                yield from flat(item)
            else:
                yield item

    targets = {o.title: reader.get_destination_page_number(o) for o in flat(reader.outline)}
    assert targets["Executive summary"] == 1
    assert targets["Entra Agent ID readiness"] == 2  # zero-based: cover, summary, readiness
    assert targets["Methodology & coverage"] > targets["Detailed findings"] > targets["Risk overview"]


def test_identity_with_many_owners_renders(demo_payload, tmp_path):
    p = demo_payload.model_copy(deep=True)
    for e in p.entities:
        e.owners = [f"person{i}@demo-corp.example" for i in range(300)]
    _, text = pdf_text(write_pdf_report(p, tmp_path / "owners.pdf"))
    assert "and 297 more" in " ".join(text.split())


def test_report_warns_before_any_command_and_states_its_limits(demo_payload, tmp_path):
    _, text = pdf_text(write_pdf_report(demo_payload, tmp_path / "r.pdf"))
    text = " ".join(text.split())
    assert "Review every command before you run it" in text
    assert "REVIEW BEFORE RUNNING" in text
    assert "full_access_as_app" in text
    assert "role-assignable groups" in text
    assert "listed as two identities" in text


def test_skipped_permission_data_is_reported_not_shown_as_zero(tmp_path):
    snap = build_demo_snapshot(NOW)
    snap.graph_app_role_assignments = None
    snap.directory_role_assignments = None
    _, text = pdf_text(write_pdf_report(run_scan(snap, now=NOW), tmp_path / "r.pdf"))
    text = " ".join(text.split())
    assert "Skipped: Graph permissions not available" in text
    assert "Skipped: directory roles not available" in text
    assert "Graph permissions, directory roles could not be evaluated" in text


def test_cli_pdf_and_from_json_roundtrip(tmp_path):
    scan_json, first_pdf, second_pdf = tmp_path / "scan.json", tmp_path / "a.pdf", tmp_path / "b.pdf"
    assert main(["--demo", "--quiet", "--json", str(scan_json), "--pdf", str(first_pdf)]) == 0
    assert main(["--from-json", str(scan_json), "--quiet", "--pdf", str(second_pdf), "--org-name", "Acme SpA"]) == 0
    _, text = pdf_text(second_pdf)
    assert "Acme SpA" in text
    assert main(["--from-json", str(scan_json), "--demo", "--quiet"]) == 1


def test_cli_rejects_invalid_saved_payload(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"metadata": {}}')
    assert main(["--from-json", str(bad), "--quiet", "--pdf", str(tmp_path / "x.pdf")]) == 1
    assert not (tmp_path / "x.pdf").exists()


def test_report_has_the_agent_id_readiness_page(demo_payload, tmp_path):
    _, text = pdf_text(write_pdf_report(demo_payload, tmp_path / "r.pdf"))
    text = " ".join(text.split())
    assert "Entra Agent ID readiness" in text and "Bring under governance first" in text
    assert "Agents already on Entra Agent ID" in text and "No owner or sponsor" in text


def test_names_with_brackets_cannot_break_the_terminal_report(tmp_path, capsys):
    snap = build_demo_snapshot(NOW)
    snap.applications[0]["displayName"] = "x [/]"
    snap.service_principals[0]["displayName"] = "[link=https://evil.example]click[/link]"
    snap.warnings = ["Sign-in activity unavailable [/] [bold]"]
    payload = run_scan(snap, now=NOW)
    render(payload, Console(width=160), "Tenant [/x]")
    out = capsys.readouterr().out
    assert "x [/]" in out and "[link=https://evil.example]click[/link]" in out and "Tenant [/x]" in out


def test_cli_scan_survives_names_with_brackets(tmp_path, monkeypatch):
    snap = build_demo_snapshot(NOW)
    snap.applications[0]["displayName"] = "x [/]"
    monkeypatch.setattr("src.nhi_scanner.demo.build_demo_snapshot", lambda: snap)
    assert main(["--demo", "--json", str(tmp_path / "s.json")]) == 0
    assert (tmp_path / "s.json").exists()


def test_failed_sign_in_gives_one_clear_message(monkeypatch, capsys):
    def no_login(**_kwargs):
        raise ClientAuthenticationError(message="\n".join(f"credential {i} unavailable" for i in range(200)))

    monkeypatch.setattr("src.nhi_scanner.collector.collect", no_login)
    assert main(["--tenant-id", "11111111-1111-4111-8111-111111111111"]) == 1
    err = " ".join(capsys.readouterr().err.split())
    assert "Run `az login" in err and "credential 7" not in err


def test_output_files_are_utf8_on_every_platform(tmp_path, monkeypatch):
    encodings = []
    real = Path.write_text

    def spy(self, data, *args, **kwargs):
        encodings.append(kwargs.get("encoding"))
        return real(self, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", spy)
    assert main(["--demo", "--quiet", "--json", str(tmp_path / "s.json"), "--schema-out", str(tmp_path / "x.json")]) == 0
    assert encodings == ["utf-8", "utf-8"]

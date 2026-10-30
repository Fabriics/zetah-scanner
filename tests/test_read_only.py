"""The promise of the tool: it reads the tenant, changes nothing and sends results nowhere."""

import ast
from pathlib import Path

SOURCES = sorted((Path(__file__).parent.parent / "src" / "nhi_scanner").glob("*.py"))
WRITE_METHODS = {"post", "put", "patch", "delete", "request"}
FORBIDDEN_MODULES = {"subprocess", "socket", "http", "urllib", "ftplib", "smtplib", "webbrowser"}


def _trees():
    return [(path.name, ast.parse(path.read_text(encoding="utf-8"))) for path in SOURCES]


def test_there_is_code_to_check():
    assert "collector.py" in {path.name for path in SOURCES}


def test_no_http_call_can_change_anything():
    calls = [
        (name, node.func.attr, node.lineno)
        for name, tree in _trees() for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in WRITE_METHODS
    ]
    assert calls == []


def test_only_the_collector_talks_to_the_network_and_only_with_get():
    uses_requests = {
        name for name, tree in _trees() for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        and ("requests" in [a.name for a in getattr(node, "names", [])] or getattr(node, "module", None) == "requests")
    }
    assert uses_requests == {"collector.py"}


def test_no_process_or_raw_network_access():
    imported = set()
    for _name, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
    assert not imported & FORBIDDEN_MODULES
    for name, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in {"system", "popen", "spawn"}, name

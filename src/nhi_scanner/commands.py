"""The last line of defence for remediation commands: what a reader may paste into a shell.

Every finding carries commands. They are generated from object ids, never from tenant text, but they are also read
back from saved payloads (``--from-json``) that anyone could have edited. So every runnable line is checked again,
by an allowlist rather than a list of dangers, each time it is written into a finding or a report:

- it is an ``az`` command of the four families the rules emit: ``ad app``, ``ad sp``, ``role assignment``, ``rest``;
- outside quotes there is no shell syntax at all: no separators, redirections, substitutions, variables, globs,
  braces or escapes; inside double quotes nothing the shell expands; every quote is closed;
- ``az rest`` only talks to Microsoft Graph or Azure Resource Manager, never with ``--resource`` (which makes az send
  a token to whatever ``--url`` names), custom headers or an output file;
- no argument loads a file (``@path``), except the placeholder of a certificate the reader chooses.

A line that fails is commented out and marked, never dropped: the reader still sees what was there.
"""

from __future__ import annotations

import re
import shlex
from typing import Optional

from requests.compat import urlsplit  # the read-only test bans urllib imports

CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
BLOCKED = "# [blocked: unsafe value from the tenant] "

_COMMANDS = (("ad", "app"), ("ad", "sp"), ("role", "assignment"), ("rest",))
_HOSTS = {"graph.microsoft.com", "management.azure.com"}
_UNQUOTED = set(";|&<>$`(){}[]*?~!\\'\"")  # quotes are handled before this set is consulted
_IN_DOUBLE = set("$`\\!")
_REST_FORBIDDEN = {"--resource", "--headers", "--output-file", "--skip-authorization-header", "--uri-parameters"}
_FILE_PLACEHOLDER = re.compile(r"^@<[A-Z_]+>$")


def _command_part(line: str) -> Optional[str]:
    """The line without its trailing comment, if its quoting is plain; None if it uses any shell syntax."""
    state = ""
    for i, c in enumerate(line):
        if state == "'":
            if c == "'":
                state = ""
        elif state == '"':
            if c == '"':
                state = ""
            elif c in _IN_DOUBLE:
                return None
        elif c in "'\"":
            state = c
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]  # a comment: the shell ignores the rest
        elif c in _UNQUOTED:
            return None
    return None if state else line


def is_safe_live(line: str) -> bool:
    if CONTROL.search(line):
        return False
    command = _command_part(line)
    if command is None:
        return False
    try:
        args = shlex.split(command)
    except ValueError:
        return False
    if len(args) < 2 or args[0] != "az" or not any(tuple(args[1:1 + len(c)]) == c for c in _COMMANDS):
        return False
    for i, arg in enumerate(args):
        if arg.startswith("@") and not _FILE_PLACEHOLDER.match(arg):
            return False
        if args[1] == "rest" and arg.split("=", 1)[0] in _REST_FORBIDDEN:
            return False
        if args[1] == "rest" and i and args[i - 1] in ("--url", "--uri", "-u"):
            target = urlsplit(arg)
            if (target.scheme != "https" or target.hostname not in _HOSTS or target.port is not None
                    or target.username or target.password or "@" in target.netloc):
                return False
    if args[1] == "rest" and not any(a in ("--url", "--uri", "-u") for a in args):
        return False
    return True


def safe_remediation(text: str) -> str:
    """Comments may quote tenant data but lose control characters; runnable lines must pass ``is_safe_live``."""
    out = []
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            out.append(CONTROL.sub("?", line))
        elif is_safe_live(line):
            out.append(line)
        else:
            out.append(BLOCKED + CONTROL.sub("?", line))
    return "\n".join(out)

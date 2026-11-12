"""The two OWASP lists the findings are mapped to.

- OWASP Top 10 Non-Human Identities Risks, 2025 edition (codes ``NHI1:2025`` … ``NHI10:2025``).
- OWASP Top 10 for Agentic Applications, 2026 edition, published in December 2025 (the document calls its entries
  ``ASI01`` … ``ASI10``; here they carry the edition, ``ASI01:2026``, so a later edition cannot be confused with it).

A rule names an entry only when its finding is an instance of that risk as OWASP describes it. Agentic entries are
named only by rules about AI agents and AI accounts; a rule that matches no entry says so with an empty mapping rather
than a loose one.
"""

from __future__ import annotations

from typing import NamedTuple

NHI_LIST = "OWASP Top 10 Non-Human Identities Risks 2025"
NHI_URL = "https://owasp.org/www-project-non-human-identities-top-10/2025/"
ASI_LIST = "OWASP Top 10 for Agentic Applications 2026"
ASI_URL = "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"


class Entry(NamedTuple):
    code: str
    title: str


NHI: dict[str, Entry] = {e.code: e for e in (
    Entry("NHI1:2025", "Improper Offboarding"),
    Entry("NHI2:2025", "Secret Leakage"),
    Entry("NHI3:2025", "Vulnerable Third-Party NHI"),
    Entry("NHI4:2025", "Insecure Authentication"),
    Entry("NHI5:2025", "Overprivileged NHI"),
    Entry("NHI6:2025", "Insecure Cloud Deployment Configurations"),
    Entry("NHI7:2025", "Long-Lived Secrets"),
    Entry("NHI8:2025", "Environment Isolation"),
    Entry("NHI9:2025", "NHI Reuse"),
    Entry("NHI10:2025", "Human Use of NHI"),
)}

ASI: dict[str, Entry] = {e.code: e for e in (
    Entry("ASI01:2026", "Agent Goal Hijack"),
    Entry("ASI02:2026", "Tool Misuse and Exploitation"),
    Entry("ASI03:2026", "Identity and Privilege Abuse"),
    Entry("ASI04:2026", "Agentic Supply Chain Vulnerabilities"),
    Entry("ASI05:2026", "Unexpected Code Execution (RCE)"),
    Entry("ASI06:2026", "Memory & Context Poisoning"),
    Entry("ASI07:2026", "Insecure Inter-Agent Communication"),
    Entry("ASI08:2026", "Cascading Failures"),
    Entry("ASI09:2026", "Human-Agent Trust Exploitation"),
    Entry("ASI10:2026", "Rogue Agents"),
)}

ENTRIES: dict[str, Entry] = {**NHI, **ASI}
MAX_PER_FINDING = 6


def order(codes: list[str] | tuple[str, ...]) -> list[str]:
    """NHI entries first, then agentic ones, each in list order: the same codes always print the same way."""
    unknown = [c for c in codes if c not in ENTRIES]
    if unknown:
        raise ValueError(f"unknown OWASP entries: {unknown}")
    rank = {c: i for i, c in enumerate(ENTRIES)}
    return sorted(codes, key=lambda c: rank[c])


def check(codes: list[str]) -> list[str]:
    """Validator for the contract: known codes, no repeats, bounded, in canonical order."""
    if len(set(codes)) != len(codes):
        raise ValueError("repeated OWASP entries")
    if len(codes) > MAX_PER_FINDING:
        raise ValueError(f"more than {MAX_PER_FINDING} OWASP entries")
    if codes != order(codes):  # also refuses unknown codes
        raise ValueError("OWASP entries out of order")
    return codes


def label(code: str) -> str:
    """'NHI5:2025 Overprivileged NHI', for reports."""
    return f"{code} {ENTRIES[code].title}"

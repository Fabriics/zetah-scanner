"""Executive PDF report for CISOs, rendered from a ``ZetahScanPayload``.

Pure reportlab (no system libraries), standard PDF fonts, A4. Sections:
cover, executive summary, risk overview, remediation plan, detailed
findings, NHI inventory, methodology & coverage.
"""

from __future__ import annotations

import functools
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (
    BaseDocTemplate,
    CondPageBreak,
    Flowable,
    Frame,
    KeepTogether,
    LongTable,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from . import __version__
from .engine import CRITICAL_CEILING, SCORE_PENALTIES
from .models import EntityType, FindingCategory, NHIEntity, SecurityFinding, Severity, ZetahScanPayload
from .readiness import agent_readiness
from .rules import RULES

# --------------------------------------------------------------------------- #
# Design tokens
# --------------------------------------------------------------------------- #

NAVY = colors.HexColor("#0B1F3A")
NAVY_2 = colors.HexColor("#163A63")
INK = colors.HexColor("#101828")
MUTED = colors.HexColor("#667085")
LINE = colors.HexColor("#E4E7EC")
PANEL = colors.HexColor("#F5F7FA")
ACCENT = colors.HexColor("#7A5AF8")
CODE_BG = colors.HexColor("#F2F4F7")

SEV_COLOR = {
    Severity.CRITICAL: colors.HexColor("#B42318"),
    Severity.HIGH: colors.HexColor("#DC6803"),
    Severity.MEDIUM: colors.HexColor("#B54708"),
    Severity.LOW: colors.HexColor("#1570EF"),
}
SEV_TINT = {
    Severity.CRITICAL: colors.HexColor("#FEF3F2"),
    Severity.HIGH: colors.HexColor("#FFF6ED"),
    Severity.MEDIUM: colors.HexColor("#FFFAEB"),
    Severity.LOW: colors.HexColor("#EFF8FF"),
}
SEV_WEIGHT = {Severity.CRITICAL: 10, Severity.HIGH: 5, Severity.MEDIUM: 2, Severity.LOW: 1}
PRIORITY = {Severity.CRITICAL: "P1", Severity.HIGH: "P2", Severity.MEDIUM: "P3", Severity.LOW: "P4"}
PRIORITY_HINT = {
    Severity.CRITICAL: "Immediately",
    Severity.HIGH: "Within 30 days",
    Severity.MEDIUM: "Within 90 days",
    Severity.LOW: "Next review cycle",
}

TYPE_LABEL = {
    EntityType.SERVICE_PRINCIPAL: "Service principal",
    EntityType.APP_REGISTRATION: "App registration",
    EntityType.MANAGED_IDENTITY: "Managed identity",
    EntityType.AI_AGENT: "AI agent",
}
CATEGORY_LABEL = {
    FindingCategory.SECRET_HYGIENE: "Secret hygiene",
    FindingCategory.DORMANT_NHI: "Dormant identities",
    FindingCategory.EXCESSIVE_GRAPH_PERMISSIONS: "Excessive Entra / Graph privilege",
    FindingCategory.AZURE_RBAC_PRIVILEGE: "Azure RBAC privilege",
    FindingCategory.AI_AGENT_GOVERNANCE: "AI agent governance",
}
CATEGORY_RECOMMENDATION = {
    FindingCategory.SECRET_HYGIENE: (
        "Eliminate static secrets. Move workloads to managed identities or workload identity federation, "
        "enforce a maximum secret lifetime (180 days or less) with an app management policy, and remove "
        "expired or unexplained credentials."
    ),
    FindingCategory.DORMANT_NHI: (
        "Decommission unused identities. Disable dormant and never-used identities, revoke their credentials, "
        "and review non-human sign-in activity at least quarterly."
    ),
    FindingCategory.EXCESSIVE_GRAPH_PERMISSIONS: (
        "Apply least privilege in Entra ID. Revoke tenant-takeover Graph permissions and privileged directory "
        "roles from workloads, and scope data access with resource-specific consent."
    ),
    FindingCategory.AZURE_RBAC_PRIVILEGE: (
        "Contain the Azure blast radius. Remove Owner and User Access Administrator from workloads and re-scope "
        "Contributor to the resource groups each pipeline actually needs."
    ),
    FindingCategory.AI_AGENT_GOVERNANCE: (
        "Govern AI agents like privileged users. Every agent needs an accountable owner, delegated or scoped "
        "permissions, no path from data access to external egress, and secretless authentication."
    ),
}
REQUIREMENT_LABEL = {
    "signin": "Skipped: sign-in activity not available",
    "azure": "Skipped: Azure RBAC not scanned",
    "graph_permissions": "Skipped: Graph permissions not available",
    "directory_roles": "Skipped: directory roles not available",
}

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
CONTENT_W = PAGE_W - 2 * MARGIN

# --------------------------------------------------------------------------- #
# Text helpers (standard PDF fonts are WinAnsi / cp1252)
# --------------------------------------------------------------------------- #

_REPLACEMENTS = {"→": "->", "≥": ">=", "≤": "<=", "✓": "v", "✗": "x", "☁️": "", " ": " "}


def _t(value: Any) -> str:
    """Safe Paragraph text: XML-escaped and limited to what the PDF fonts can draw."""
    text = "" if value is None else str(value)
    for src, dst in _REPLACEMENTS.items():
        text = text.replace(src, dst)
    text = "".join(c if c in "\n\t" or _encodable(c) else "?" for c in text)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


@functools.lru_cache(maxsize=4096)
def _encodable(c: str) -> bool:
    try:
        c.encode("cp1252")
        return True
    except UnicodeEncodeError:
        return False


def _hex(c: colors.Color) -> str:
    return "#" + c.hexval()[2:]


def _date(d: Optional[datetime], with_time: bool = False) -> str:
    if d is None:
        return "-"
    return d.strftime("%d %b %Y %H:%M UTC" if with_time else "%d %b %Y")


def _owners_label(owners: list[str], limit: int = 3) -> str:
    """Shortened owner list: reportlab cannot split a table row taller than a page."""
    extra = len(owners) - limit
    return ", ".join(owners[:limit]) + (f" and {extra} more" if extra > 0 else "")


def _humanize_key(key: str) -> str:
    return key.replace("_", " ").capitalize()


_ISO_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _fmt_scalar(v: Any) -> str:
    if isinstance(v, bool):
        return "yes" if v else "no"
    if v is None:
        return "-"
    if isinstance(v, str) and _ISO_TS.match(v):
        return _date(datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ"))
    if isinstance(v, str) and v in {"client_secret", "certificate"}:
        return v.replace("_", " ")
    return str(v)


def _evidence_lines(evidence: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for key, value in evidence.items():
        label = f"<b>{_t(_humanize_key(key))}:</b>"
        if isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
            lines.append(label)
            for item in value:
                pairs = " · ".join(f"{_t(_humanize_key(k))}: {_t(_fmt_scalar(v))}" for k, v in item.items())
                lines.append(f"&nbsp;&nbsp;&nbsp;• {pairs}")
        elif isinstance(value, list):
            lines.append(f"{label} {_t(', '.join(_fmt_scalar(v) for v in value)) or '-'}")
        elif isinstance(value, dict):
            pairs = ", ".join(f"{_humanize_key(k)}={_fmt_scalar(v)}" for k, v in value.items())
            lines.append(f"{label} {_t(pairs)}")
        else:
            lines.append(f"{label} {_t(_fmt_scalar(value))}")
    return lines


# --------------------------------------------------------------------------- #
# Styles
# --------------------------------------------------------------------------- #


def _styles() -> dict[str, ParagraphStyle]:
    base = ParagraphStyle("base", fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK)
    s = {
        "body": base,
        "lead": ParagraphStyle("lead", parent=base, spaceAfter=5),
        "small": ParagraphStyle("small", parent=base, fontSize=8, leading=10.5, textColor=MUTED),
        "tiny": ParagraphStyle("tiny", parent=base, fontSize=7, leading=9, textColor=MUTED),
        "h1": ParagraphStyle("H1", parent=base, fontName="Helvetica-Bold", fontSize=20, leading=24,
                             textColor=NAVY, spaceAfter=4),
        "h1sub": ParagraphStyle("h1sub", parent=base, fontSize=10, leading=14, textColor=MUTED, spaceAfter=12),
        "h2": ParagraphStyle("H2", parent=base, fontName="Helvetica-Bold", fontSize=12.5, leading=16,
                             textColor=NAVY, spaceBefore=10, spaceAfter=6),
        "h3": ParagraphStyle("h3", parent=base, fontName="Helvetica-Bold", fontSize=10.5, leading=14, textColor=INK),
        "label": ParagraphStyle("label", parent=base, fontName="Helvetica-Bold", fontSize=7.5, leading=10,
                                textColor=MUTED, spaceBefore=6, spaceAfter=2),
        "cell": ParagraphStyle("cell", parent=base, fontSize=8, leading=10.5),
        "cellb": ParagraphStyle("cellb", parent=base, fontName="Helvetica-Bold", fontSize=8, leading=10.5),
        "cellhead": ParagraphStyle("cellhead", parent=base, fontName="Helvetica-Bold", fontSize=7.5, leading=10,
                                   textColor=colors.white),
        "code": ParagraphStyle("code", parent=base, fontName="Courier", fontSize=7.3, leading=9.6,
                               textColor=INK, wordWrap="CJK"),
        "codecomment": ParagraphStyle("codecomment", parent=base, fontName="Courier-Oblique", fontSize=7.3,
                                      leading=9.6, textColor=MUTED, wordWrap="CJK"),
        "evidence": ParagraphStyle("evidence", parent=base, fontSize=8, leading=11, wordWrap="CJK"),
        "bullet": ParagraphStyle("bullet", parent=base, leftIndent=12, bulletIndent=0, spaceAfter=4),
        "metric_value": ParagraphStyle("mv", parent=base, fontName="Helvetica-Bold", fontSize=17, leading=20,
                                       textColor=NAVY),
        "metric_label": ParagraphStyle("ml", parent=base, fontSize=7.5, leading=9.5, textColor=MUTED),
        "tile_value": ParagraphStyle("tv", parent=base, fontName="Helvetica-Bold", fontSize=20, leading=23,
                                     textColor=colors.white, alignment=TA_CENTER),
        "tile_label": ParagraphStyle("tl", parent=base, fontName="Helvetica-Bold", fontSize=7.5, leading=9.5,
                                     textColor=colors.white, alignment=TA_CENTER),
    }
    return s


# --------------------------------------------------------------------------- #
# Custom flowables
# --------------------------------------------------------------------------- #


def score_band(score: int) -> tuple[str, colors.Color]:
    if score >= 80:
        return "Good", colors.HexColor("#079455")
    if score >= 50:
        return "Needs attention", colors.HexColor("#DC6803")
    return "At risk", colors.HexColor("#B42318")


class ScoreGauge(Flowable):
    """Ring gauge with the hygiene score in the middle."""

    def __init__(self, score: int, size: float = 42 * mm, dark: bool = False):
        super().__init__()
        self.score, self.size, self.dark = score, size, dark
        self.width = self.height = size

    def draw(self) -> None:
        c = self.canv
        label, color = score_band(self.score)
        r = self.size / 2
        stroke = self.size * 0.09
        inset = stroke / 2 + 1
        c.setLineCap(1)
        c.setLineWidth(stroke)
        c.setStrokeColor(colors.HexColor("#2B4A73") if self.dark else LINE)
        c.circle(r, r, r - inset, stroke=1, fill=0)
        if self.score > 0:
            c.setStrokeColor(color)
            extent = -359.9 * self.score / 100
            c.arc(inset, inset, self.size - inset, self.size - inset, startAng=90, extent=extent)
        text = colors.white if self.dark else NAVY
        c.setFillColor(text)
        c.setFont("Helvetica-Bold", self.size * 0.30)
        c.drawCentredString(r, r - self.size * 0.04, str(self.score))
        c.setFont("Helvetica", self.size * 0.062)
        c.setFillColor(colors.HexColor("#C7D2E0") if self.dark else MUTED)
        c.drawCentredString(r, r - self.size * 0.16, "SCORE / 100")
        c.setFillColor(color)
        c.setFont("Helvetica-Bold", self.size * 0.085)
        c.drawCentredString(r, r + self.size * 0.20, label.upper())


class StackedBars(Flowable):
    """Horizontal bars, one per row, each split into severity segments."""

    def __init__(self, rows: list[tuple[str, dict[Severity, int]]], width: float, bar_h: float = 5.2 * mm):
        super().__init__()
        self.rows, self.width, self.bar_h = rows, width, bar_h
        self.label_w = 58 * mm
        self.row_gap = 3.2 * mm
        self.height = len(rows) * (bar_h + self.row_gap) + 9 * mm

    def draw(self) -> None:
        c = self.canv
        total_max = max([sum(v.values()) for _, v in self.rows] + [1])
        plot_w = self.width - self.label_w - 12 * mm
        y = self.height - self.bar_h - 1 * mm
        for label, counts in self.rows:
            c.setFont("Helvetica", 8)
            c.setFillColor(INK)
            c.drawString(0, y + self.bar_h / 2 - 3, label)
            x = self.label_w
            c.setFillColor(PANEL)
            c.rect(x, y, plot_w, self.bar_h, stroke=0, fill=1)
            total = 0
            for sev in Severity:
                n = counts.get(sev, 0)
                if not n:
                    continue
                w = plot_w * n / total_max
                c.setFillColor(SEV_COLOR[sev])
                c.rect(x, y, w, self.bar_h, stroke=0, fill=1)
                if w > 9:
                    c.setFillColor(colors.white)
                    c.setFont("Helvetica-Bold", 7)
                    c.drawCentredString(x + w / 2, y + self.bar_h / 2 - 2.5, str(n))
                x += w
                total += n
            c.setFillColor(INK)
            c.setFont("Helvetica-Bold", 8)
            c.drawString(x + 2 * mm, y + self.bar_h / 2 - 3, str(total))
            y -= self.bar_h + self.row_gap
        # legend
        x = self.label_w
        for sev in Severity:
            c.setFillColor(SEV_COLOR[sev])
            c.rect(x, 1 * mm, 3 * mm, 3 * mm, stroke=0, fill=1)
            c.setFillColor(MUTED)
            c.setFont("Helvetica", 7)
            c.drawString(x + 4.2 * mm, 1.6 * mm, sev.value.capitalize())
            x += 22 * mm


class SectionRule(Flowable):
    def __init__(self, width: float, color: colors.Color = ACCENT, thickness: float = 2):
        super().__init__()
        self.width, self.color, self.thickness = width, color, thickness
        self.height = thickness + 2

    def draw(self) -> None:
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(self.thickness)
        self.canv.line(0, 1, 28 * mm, 1)
        self.canv.setStrokeColor(LINE)
        self.canv.setLineWidth(0.6)
        self.canv.line(28 * mm, 1, self.width, 1)


# --------------------------------------------------------------------------- #
# Document scaffolding
# --------------------------------------------------------------------------- #


class _NumberedCanvas(rl_canvas.Canvas):
    """Defers page output so every page can show "Page x of y"."""

    def __init__(self, *args: Any, decorate: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._saved: list[dict[str, Any]] = []
        self._decorate = decorate
        self._bookmarks: list[tuple[str, str, int]] = []

    def defer_bookmark(self, key: str, title: str, level: int) -> None:
        self._bookmarks.append((key, title, level))

    def showPage(self) -> None:  # noqa: N802 — reportlab API
        self._saved.append(dict(self.__dict__))
        self._bookmarks = []
        self._startPage()

    def save(self) -> None:
        total = len(self._saved)
        for state in self._saved:
            self.__dict__.update(state)
            # Pages are only written here, so a bookmark set earlier would point at the first page
            for key, title, level in self._bookmarks:
                self.bookmarkPage(key)
                self.addOutlineEntry(title, key, level=level, closed=True)
            self._decorate(self, self._pageNumber, total)
            super().showPage()
        super().save()


class _Doc(BaseDocTemplate):
    def afterFlowable(self, flowable: Flowable) -> None:  # noqa: N802 — reportlab API
        if isinstance(flowable, Paragraph) and flowable.style.name in {"H1", "H2"}:
            text = re.sub(r"<[^>]+>", "", flowable.getPlainText())
            self.canv.defer_bookmark(f"h{id(flowable)}", text, 0 if flowable.style.name == "H1" else 1)


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #


class _Report:
    def __init__(self, payload: ZetahScanPayload, org_name: str):
        self.p = payload
        self.md = payload.metadata
        self.org = org_name
        self.s = _styles()
        self.entities = {e.entity_id: e for e in payload.entities}
        self.by_entity: dict[str, list[SecurityFinding]] = defaultdict(list)
        for f in payload.findings:
            self.by_entity[f.entity_id].append(f)
        self.rules = {r.rule_id: r for r in RULES}
        self.generated = datetime.now(timezone.utc)
        self.signins_known = any(r.startswith("NHI-DORM") for r in self.md.rules_evaluated)
        self.azure_known = any(r.startswith("NHI-RBAC") for r in self.md.rules_evaluated)
        self.permissions_known = "NHI-PERM-001" in self.md.rules_evaluated
        self.roles_known = "NHI-PERM-003" in self.md.rules_evaluated

    # ---- small builders -------------------------------------------------- #

    def para(self, text: str, style: str = "body") -> Paragraph:
        return Paragraph(text, self.s[style])

    def h1(self, title: str, subtitle: str) -> list[Flowable]:
        return [self.para(_t(title), "h1"), SectionRule(CONTENT_W), Spacer(1, 4), self.para(subtitle, "h1sub")]

    def badge(self, sev: Severity, width: float = 17 * mm) -> Table:
        t = Table([[Paragraph(f'<font color="white"><b>{sev.value}</b></font>',
                              ParagraphStyle("b", fontName="Helvetica-Bold", fontSize=6.8, leading=8,
                                             alignment=TA_CENTER))]],
                  colWidths=[width], rowHeights=[4.6 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), SEV_COLOR[sev]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 1), ("RIGHTPADDING", (0, 0), (-1, -1), 1),
            ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        return t

    def data_table(self, header: list[str], rows: list[list[Any]], widths: list[float],
                   zebra: bool = True, extra_style: Iterable[tuple] = ()) -> LongTable:
        data = [[self.para(_t(h), "cellhead") for h in header]] + rows
        t = LongTable(data, colWidths=widths, repeatRows=1)
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LINEBELOW", (0, 1), (-1, -1), 0.4, LINE),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]
        if zebra:
            style.append(("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PANEL]))
        t.setStyle(TableStyle(style + list(extra_style)))
        return t

    def worst(self, findings: list[SecurityFinding]) -> Optional[Severity]:
        return max((f.severity for f in findings), key=lambda s: s.rank, default=None)

    def entity_label(self, e: NHIEntity) -> str:
        return f"{_t(e.display_name)}<br/><font size=6.5 color='{_hex(MUTED)}'>{TYPE_LABEL[e.entity_type]}</font>"

    # ---- page decoration ------------------------------------------------- #

    def decorate(self, c: rl_canvas.Canvas, page: int, total: int) -> None:
        if page == 1:
            return
        c.saveState()
        c.setStrokeColor(LINE)
        c.setLineWidth(0.5)
        c.line(MARGIN, PAGE_H - 12 * mm, PAGE_W - MARGIN, PAGE_H - 12 * mm)
        c.line(MARGIN, 12 * mm, PAGE_W - MARGIN, 12 * mm)
        c.setFont("Helvetica-Bold", 7.5)
        c.setFillColor(NAVY)
        c.drawString(MARGIN, PAGE_H - 10 * mm, "ZETAH")
        c.setFont("Helvetica", 7.5)
        c.setFillColor(MUTED)
        c.drawString(MARGIN + 11.5 * mm, PAGE_H - 10 * mm, "Non-Human Identity Security Assessment")
        c.drawRightString(PAGE_W - MARGIN, PAGE_H - 10 * mm, _t(self.org)[:70].replace("&amp;", "&"))
        c.setFillColor(SEV_COLOR[Severity.CRITICAL])
        c.setFont("Helvetica-Bold", 7)
        c.drawString(MARGIN, 8 * mm, "CONFIDENTIAL")
        c.setFillColor(MUTED)
        c.setFont("Helvetica", 7)
        c.drawCentredString(PAGE_W / 2, 8 * mm, f"Scan {str(self.md.scan_id)[:8]} · {_date(self.md.scan_timestamp)}")
        c.drawRightString(PAGE_W - MARGIN, 8 * mm, f"Page {page} of {total}")
        c.restoreState()

    def draw_cover(self, c: rl_canvas.Canvas, _doc: Any) -> None:
        c.saveState()
        band_h = PAGE_H * 0.58
        c.setFillColor(NAVY)
        c.rect(0, PAGE_H - band_h, PAGE_W, band_h, stroke=0, fill=1)
        c.setFillColor(ACCENT)
        c.rect(0, PAGE_H - band_h - 1.6 * mm, PAGE_W, 1.6 * mm, stroke=0, fill=1)

        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 13)
        c.drawString(MARGIN, PAGE_H - 22 * mm, "ZETAH")
        c.setFont("Helvetica", 8)
        c.setFillColor(colors.HexColor("#C7D2E0"))
        c.drawString(MARGIN + 17 * mm, PAGE_H - 22 * mm, "scanner")
        c.setFillColor(SEV_COLOR[Severity.CRITICAL])
        c.roundRect(PAGE_W - MARGIN - 30 * mm, PAGE_H - 24 * mm, 30 * mm, 6.5 * mm, 1.5 * mm, stroke=0, fill=1)
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 7.5)
        c.drawCentredString(PAGE_W - MARGIN - 15 * mm, PAGE_H - 21.8 * mm, "CONFIDENTIAL")

        c.setFont("Helvetica", 10)
        c.setFillColor(colors.HexColor("#A9B8CC"))
        c.drawString(MARGIN, PAGE_H - 70 * mm, "SECURITY ASSESSMENT REPORT")
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 28)
        c.drawString(MARGIN, PAGE_H - 84 * mm, "Non-Human Identity")
        c.drawString(MARGIN, PAGE_H - 96 * mm, "Security Assessment")
        c.setFont("Helvetica", 11)
        c.setFillColor(colors.HexColor("#C7D2E0"))
        c.drawString(MARGIN, PAGE_H - 106 * mm, "Microsoft Entra ID & Azure · service principals, app registrations,")
        c.drawString(MARGIN, PAGE_H - 112 * mm, "managed identities and AI agents")

        c.setFont("Helvetica-Bold", 15)
        c.setFillColor(colors.white)
        org = _t(self.org).replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        c.drawString(MARGIN, PAGE_H - 130 * mm, org[:48])
        c.setFont("Helvetica", 8.5)
        c.setFillColor(colors.HexColor("#A9B8CC"))
        c.drawString(MARGIN, PAGE_H - 136 * mm, f"Tenant ID {self.md.tenant_id}")

        gauge = ScoreGauge(self.md.hygiene_score, size=50 * mm, dark=True)
        gauge.canv = c
        c.saveState()
        c.translate(PAGE_W - MARGIN - 50 * mm, PAGE_H - 140 * mm)
        gauge.draw()
        c.restoreState()

        # details block on white
        y = PAGE_H - band_h - 18 * mm
        sc = self.md.summary_counts
        rows = [
            ("Scan date", _date(self.md.scan_timestamp, with_time=True)),
            ("Report generated", _date(self.generated, with_time=True)),
            ("Scope", f"{sc.total_entities} non-human identities · {sc.total_findings} findings"),
            ("Scan ID", str(self.md.scan_id)),
            ("Scanner", f"zetah-scanner {self.md.scanner_version} (read-only)"),
        ]
        for label, value in rows:
            c.setFont("Helvetica-Bold", 8)
            c.setFillColor(MUTED)
            c.drawString(MARGIN, y, label.upper())
            c.setFont("Helvetica", 10)
            c.setFillColor(INK)
            c.drawString(MARGIN + 42 * mm, y, value)
            y -= 9 * mm

        x = MARGIN
        tile_w = (CONTENT_W - 3 * 4 * mm) / 4
        for sev in Severity:
            n = getattr(sc.by_severity, sev.value.lower())
            c.setFillColor(SEV_COLOR[sev])
            c.roundRect(x, 34 * mm, tile_w, 18 * mm, 2 * mm, stroke=0, fill=1)
            c.setFillColor(colors.white)
            c.setFont("Helvetica-Bold", 18)
            c.drawCentredString(x + tile_w / 2, 42 * mm, str(n))
            c.setFont("Helvetica-Bold", 7)
            c.drawCentredString(x + tile_w / 2, 37 * mm, sev.value)
            x += tile_w + 4 * mm

        c.setFont("Helvetica", 7)
        c.setFillColor(MUTED)
        c.drawString(MARGIN, 18 * mm, "This report contains security-sensitive information about identities, privileges and attack paths.")
        c.drawString(MARGIN, 14 * mm, "Distribute on a need-to-know basis only.")
        c.restoreState()

    # ---- sections ---------------------------------------------------------- #

    def executive_summary(self) -> list[Flowable]:
        md, sc = self.md, self.md.summary_counts
        band, band_color = score_band(md.hygiene_score)
        out = self.h1("Executive summary", f"Point-in-time assessment of {_t(self.org)} · {_date(md.scan_timestamp)}")

        out.append(Table(
            [[ScoreGauge(md.hygiene_score, 40 * mm), [self.para(p, "lead") for p in self.narrative()]]],
            colWidths=[48 * mm, CONTENT_W - 48 * mm],
            style=TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                              ("RIGHTPADDING", (0, 0), (0, 0), 8 * mm)]),
        ))
        out.append(Spacer(1, 8))

        tiles = []
        for sev in Severity:
            n = getattr(sc.by_severity, sev.value.lower())
            tiles.append([self.para(str(n), "tile_value"), self.para(f"{sev.value} · {PRIORITY_HINT[sev].upper()}",
                                                                   "tile_label")])
        tw = (CONTENT_W - 9) / 4
        t = Table([tiles], colWidths=[tw] * 4)
        t.setStyle(TableStyle(
            [("BACKGROUND", (i, 0), (i, 0), SEV_COLOR[sev]) for i, sev in enumerate(Severity)]
            + [("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 7),
               ("BOTTOMPADDING", (0, 0), (-1, -1), 8), ("LINEAFTER", (0, 0), (2, 0), 3, colors.white)]
        ))
        out += [t, Spacer(1, 10)]

        out.append(self.para("Key indicators", "h2"))
        out.append(self.metrics_grid())

        out.append(self.para("Top risks", "h2"))
        top = [f for f in self.p.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)][:6] or self.p.findings[:6]
        if top:
            for f in top:
                e = self.entities[f.entity_id]
                out.append(Table(
                    [[self.badge(f.severity), self.para(
                        f"<b>{_t(f.title)}</b> <font color='{_hex(MUTED)}'>· {_t(e.display_name)} "
                        f"({TYPE_LABEL[e.entity_type].lower()})</font>", "cell")]],
                    colWidths=[20 * mm, CONTENT_W - 20 * mm],
                    style=TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                      ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]),
                ))
        else:
            out.append(self.para("No findings were raised in this assessment."))

        recs = self.recommendations()
        if recs:
            out.append(CondPageBreak(50 * mm))
            out.append(self.para("Strategic recommendations", "h2"))
            for i, (cat, text) in enumerate(recs, 1):
                head, _, rest = text.partition(". ")
                out.append(self.para(f"<b>{i}. {_t(head)}.</b> {_t(rest)}", "bullet"))
        return out

    def agent_id_readiness(self) -> list[Flowable]:
        r = agent_readiness(self.p)
        out = self.h1(
            "Entra Agent ID readiness",
            "Where this tenant's AI agents stand before adopting Microsoft Entra Agent ID: which already are agent "
            "identities, which still run as ordinary identities, who is accountable for them, and which to bring "
            "under governance first.",
        )
        total = len(r.agents)
        accountable = f"{r.accountable} of {total}" + (f" ({r.unknown} unknown)" if r.unknown else "")
        tiles = [
            (str(total), "AI AGENTS FOUND"),
            (str(r.count("agent_id")) if r.agent_id_readable else "Unknown", "ON ENTRA AGENT ID"),
            (str(r.count("legacy")), "OUTSIDE AGENT ID"),
            (accountable, "WITH AN ACCOUNTABLE PERSON"),
        ]
        tw = (CONTENT_W - 9) / 4
        t = Table([[[self.para(_t(v), "tile_value"), self.para(label, "tile_label")] for v, label in tiles]],
                  colWidths=[tw] * 4)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), NAVY), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                               ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                               ("LINEAFTER", (0, 0), (2, 0), 3, colors.white)]))
        out += [t, Spacer(1, 10)]
        unreadable = (
            "Entra Agent ID identities could not be read in this scan (the scanning identity needs "
            "AgentIdentity.Read.All), so agents created with Agent ID may be missing from this page."
        )
        if not total:
            out.append(self.para(
                "No AI agents were identified. Agents that are not Entra Agent ID objects are found from tags and "
                "naming patterns, so unlabelled agents may still exist among the service principals."))
            return out + ([] if r.agent_id_readable else [Spacer(1, 6), self.para(unreadable)])

        out.append(self.para("Bring under governance first", "h2"))
        first = r.govern_first()
        if first:
            out.append(self.para(
                "Agents running as ordinary identities with open findings, riskiest first. They carry the "
                "permissions and credentials an attacker would use, without the sponsor and lifecycle that Agent ID "
                "adds.", "body"))
            rows = []
            for i, a in enumerate(first, 1):
                owner = {True: _t(_owners_label(a.entity.owners)), None: "Unknown",
                         False: "<font color='%s'><b>Nobody</b></font>" % _hex(SEV_COLOR[Severity.CRITICAL])}[a.accountable]
                where = ("Managed identity" if a.entity.raw_metadata.get("servicePrincipalType") == "ManagedIdentity"
                         else "App registration / service principal")
                label = f"{_t(a.entity.display_name)}<br/><font size=6.5 color='{_hex(MUTED)}'>{where}</font>"
                rows.append([
                    self.para(str(i), "cell"), self.para(label, "cell"), self.badge(a.worst),
                    self.para(str(len(a.findings)), "cell"),
                    self.para("<br/>".join(sorted({_t(f.rule_id) for f in a.findings})), "cell"),
                    self.para(owner, "cell"),
                ])
            w = CONTENT_W
            out.append(self.data_table(["#", "Agent", "Worst", "Findings", "Rules", "Accountable"], rows,
                                       [w * 0.05, w * 0.31, w * 0.13, w * 0.10, w * 0.17, w * 0.24]))
        else:
            out.append(self.para("No agent outside Agent ID has open findings."))

        on_id = [a for a in r.agents if a.kind in ("agent_id", "blueprint")]
        out.append(self.para("Agents already on Entra Agent ID", "h2"))
        if on_id:
            rows = []
            for a in sorted(on_id, key=lambda a: a.risk, reverse=True):
                kind = "Agent identity" if a.kind == "agent_id" else "Agent identity blueprint"
                who = {True: _t(_owners_label(a.entity.owners)), None: "Sponsors not readable",
                       False: "<font color='%s'><b>No owner or sponsor</b></font>" % _hex(SEV_COLOR[Severity.CRITICAL])}
                rows.append([
                    self.para(f"<b>{_t(a.entity.display_name)}</b><br/><font size=6.5 color='{_hex(MUTED)}'>{kind}"
                              "</font>", "cell"),
                    self.para(who[a.accountable], "cell"),
                    self.badge(a.worst) if a.worst else self.para("-", "cell"),
                    self.para(str(len(a.findings)), "cell"),
                ])
            w = CONTENT_W
            out.append(self.data_table(["Agent", "Owner or sponsor", "Worst", "Findings"], rows,
                                       [w * 0.38, w * 0.34, w * 0.15, w * 0.13]))
        elif r.agent_id_readable:
            out.append(self.para("None yet: every AI agent found runs as an ordinary identity."))
        else:
            out.append(self.para(unreadable))
        out.append(Spacer(1, 6))
        out.append(self.para(
            f"<font color='{_hex(MUTED)}'>Readiness here means visibility and identity hygiene. It does not assess "
            "licensing or how agents are migrated to Agent ID.</font>", "body"))
        return out

    def narrative(self) -> list[str]:
        md, sc = self.md, self.md.summary_counts
        band, color = score_band(md.hygiene_score)
        types = sc.by_entity_type
        parts = [
            f"<b>{_t(self.org)}</b> scored <b><font color='{_hex(color)}'>{md.hygiene_score}/100 ({band})</font></b>. "
            f"The assessment inventoried <b>{sc.total_entities}</b> non-human identities "
            f"({types.app_registration} app registrations, {types.service_principal} service principals, "
            f"{types.managed_identity} managed identities, {types.ai_agent} AI agents) "
            f"and raised <b>{sc.total_findings}</b> findings."
        ]
        crit = sc.by_severity.critical
        if crit:
            parts.append(
                f"<b>{crit} critical finding{'s' if crit != 1 else ''}</b> represent direct paths to tenant or Azure "
                "takeover, or a likely persistence mechanism, and should be remediated immediately."
            )
        if sc.orphaned_identities:
            pct = round(100 * sc.orphaned_identities / max(sc.total_entities, 1))
            parts.append(
                f"<b>{sc.orphaned_identities} identities ({pct}%)</b> have no accountable owner, so nobody reviews "
                "their credentials or permissions."
            )
        agents = [e for e in self.p.entities if e.entity_type is EntityType.AI_AGENT]
        if agents:
            risky = sum(1 for a in agents if self.by_entity.get(a.entity_id))
            parts.append(
                f"<b>{len(agents)} AI agent{'s' if len(agents) != 1 else ''}</b> were identified; "
                f"{risky} carr{'y' if risky != 1 else 'ies'} governance or privilege findings."
            )
        missing = [n for n, ok in (("Graph permissions", self.permissions_known), ("directory roles", self.roles_known),
                                   ("sign-in activity", self.signins_known), ("Azure RBAC", self.azure_known)) if not ok]
        if missing:
            parts.append(
                f"<font color='{_hex(MUTED)}'>Coverage note: {', '.join(missing)} could not be evaluated; "
                "see Methodology &amp; coverage.</font>"
            )
        return parts

    def metrics_grid(self) -> Table:
        sc = self.md.summary_counts
        rules = Counter(f.rule_id for f in self.p.findings)
        privileged = {
            f.entity_id for f in self.p.findings
            if f.rule_id in {"NHI-PERM-001", "NHI-RBAC-001"}
            or (f.rule_id == "NHI-PERM-003" and f.severity is Severity.CRITICAL)
        }
        metrics = [
            (str(sc.total_entities), "Non-human identities"),
            (str(sc.orphaned_identities), "Orphaned (no owner)"),
            (str(len(privileged)) if self.permissions_known and self.roles_known else "n/a",
             "Identities with tenant / Azure takeover rights"),
            (str(sc.by_entity_type.ai_agent), "AI agents identified"),
            (str(rules["NHI-DORM-001"] + rules["NHI-DORM-002"]) if self.signins_known else "n/a",
             "Dormant or unused with valid credentials"),
            (str(rules["NHI-SEC-002"]), "Apps with long-lived secrets"),
            (str(rules["NHI-SEC-004"]), "Service principals with hidden credentials"),
            (str(rules["NHI-AGENT-003"]) if self.permissions_known else "n/a", "AI agents with an exfiltration path"),
        ]
        cells = [[self.para(v, "metric_value"), self.para(_t(l), "metric_label")] for v, l in metrics]
        rows = [cells[i:i + 4] for i in range(0, len(cells), 4)]
        w = CONTENT_W / 4
        t = Table(rows, colWidths=[w] * 4)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), PANEL),
            ("LINEAFTER", (0, 0), (2, -1), 3, colors.white),
            ("LINEBELOW", (0, 0), (-1, 0), 3, colors.white),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        return t

    def recommendations(self) -> list[tuple[FindingCategory, str]]:
        per_cat: dict[FindingCategory, list[SecurityFinding]] = defaultdict(list)
        for f in self.p.findings:
            per_cat[f.category].append(f)
        ordered = sorted(per_cat, key=lambda c: (-max(f.severity.rank for f in per_cat[c]), -len(per_cat[c])))
        return [(c, CATEGORY_RECOMMENDATION[c]) for c in ordered]

    def risk_overview(self) -> list[Flowable]:
        out = self.h1("Risk overview", "Where the exposure sits, by risk category and by identity.")
        out.append(self.para("Findings by category and severity", "h2"))
        rows = []
        for cat in FindingCategory:
            counts = Counter(f.severity for f in self.p.findings if f.category is cat)
            rows.append((CATEGORY_LABEL[cat], dict(counts)))
        out.append(StackedBars(rows, CONTENT_W))

        out.append(self.para("Identity inventory composition", "h2"))
        inv_rows = []
        for et in EntityType:
            ents = [e for e in self.p.entities if e.entity_type is et]
            with_findings = sum(1 for e in ents if self.by_entity.get(e.entity_id))
            orphaned = sum(1 for e in ents if e.is_orphaned)
            worst = self.worst([f for e in ents for f in self.by_entity.get(e.entity_id, [])])
            inv_rows.append([
                self.para(TYPE_LABEL[et], "cellb"), self.para(str(len(ents)), "cell"),
                self.para(str(with_findings), "cell"), self.para(str(orphaned), "cell"),
                self.badge(worst) if worst else self.para("-", "cell"),
            ])
        w = CONTENT_W
        out.append(self.data_table(["Identity type", "Count", "With findings", "Orphaned", "Worst severity"],
                                   inv_rows, [w * 0.34, w * 0.14, w * 0.18, w * 0.14, w * 0.20]))

        out.append(self.para("Most exposed identities", "h2"))
        ranked = sorted(
            (e for e in self.p.entities if self.by_entity.get(e.entity_id)),
            key=lambda e: -sum(SEV_WEIGHT[f.severity] for f in self.by_entity[e.entity_id]),
        )[:8]
        rows = []
        for i, e in enumerate(ranked, 1):
            fs = self.by_entity[e.entity_id]
            owner = "<font color='%s'><b>None (orphaned)</b></font>" % _hex(SEV_COLOR[Severity.CRITICAL]) \
                if e.is_orphaned else _t(_owners_label(e.owners) or "n/a (by design)")
            rows.append([
                self.para(str(i), "cell"), self.para(self.entity_label(e), "cell"),
                self.badge(self.worst(fs)), self.para(str(len(fs)), "cell"),
                self.para("<br/>".join(sorted({_t(f.rule_id) for f in fs})), "cell"),
                self.para(owner, "cell"),
            ])
        if rows:
            out.append(self.data_table(["#", "Identity", "Worst", "Findings", "Rules", "Owner"], rows,
                                       [w * 0.05, w * 0.30, w * 0.13, w * 0.10, w * 0.17, w * 0.25]))
        else:
            out.append(self.para("No identity has open findings."))
        return out

    def remediation_plan(self) -> list[Flowable]:
        out = self.h1(
            "Remediation plan",
            "Every finding, ordered by priority. P1 items enable tenant or Azure takeover and should be handled "
            "immediately; detailed commands are in the next section.",
        )
        if not self.p.findings:
            return out + [self.para("Nothing to remediate.")]
        rows = []
        for i, f in enumerate(self.p.findings, 1):
            rule = self.rules.get(f.rule_id)
            rows.append([
                self.para(f"<b>{PRIORITY[f.severity]}</b><br/><font size=6.5 color='{_hex(MUTED)}'>"
                          f"{PRIORITY_HINT[f.severity]}</font>", "cell"),
                self.para(f"<font color='{_hex(MUTED)}'>{i:02d}</font> {_t(f.title)}<br/>"
                          f"<font size=6.5 color='{_hex(MUTED)}'>{_t(f.rule_id)}</font>", "cell"),
                self.para(self.entity_label(self.entities[f.entity_id]), "cell"),
                self.para(_t(rule.action if rule else "See detailed findings"), "cell"),
            ])
        w = CONTENT_W
        sev_style = [("LINEBEFORE", (0, i), (0, i), 3, SEV_COLOR[f.severity]) for i, f in enumerate(self.p.findings, 1)]
        out.append(self.data_table(["Priority", "Issue", "Identity", "Recommended action"], rows,
                                   [w * 0.13, w * 0.37, w * 0.22, w * 0.28], extra_style=sev_style))
        return out

    def detailed_findings(self) -> list[Flowable]:
        out = self.h1("Detailed findings",
                      "Technical detail for each finding: what was found, how it can be abused, the evidence "
                      "collected and the commands to fix it.")
        out.append(Table(
            [[self.para(
                "<b>Review every command before you run it.</b> These commands change a live tenant and come from a "
                "point-in-time scan: check that they still apply, understand what depends on the identity, and run "
                "them in a change window. Steps that could break a running workload are commented out on purpose: "
                "uncomment them only after the check described above them.", "cell")]],
            colWidths=[CONTENT_W],
            style=TableStyle([("BACKGROUND", (0, 0), (-1, -1), SEV_TINT[Severity.HIGH]),
                              ("LINEBEFORE", (0, 0), (0, -1), 2, SEV_COLOR[Severity.HIGH]),
                              ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                              ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]),
        ))
        out.append(Spacer(1, 12))
        for i, f in enumerate(self.p.findings, 1):
            e = self.entities[f.entity_id]
            head = Table(
                [[self.badge(f.severity, 19 * mm),
                  self.para(f"<font color='{_hex(MUTED)}'>{i:02d}</font>&nbsp;&nbsp;<b>{_t(f.title)}</b>", "h3")]],
                colWidths=[22 * mm, CONTENT_W - 22 * mm],
                style=TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                  ("BACKGROUND", (0, 0), (-1, -1), SEV_TINT[f.severity]),
                                  ("LEFTPADDING", (0, 0), (0, 0), 5),
                                  ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                                  ("LINEBEFORE", (0, 0), (0, 0), 3, SEV_COLOR[f.severity])]),
            )
            meta = self.para(
                f"<b>{_t(e.display_name)}</b> · {TYPE_LABEL[e.entity_type]} · Object ID {_t(e.entity_id)}"
                + (f" · App ID {_t(e.app_id)}" if e.app_id else "")
                + f"<br/>Rule {_t(f.rule_id)} · {CATEGORY_LABEL[f.category]} · Priority {PRIORITY[f.severity]} "
                  f"({PRIORITY_HINT[f.severity].lower()}) · Finding ID {f.finding_id[:16]}",
                "small",
            )
            attack = Table(
                [[self.para(f"<b>Attack path.</b> {_t(f.attack_path_context)}", "cell")]],
                colWidths=[CONTENT_W],
                style=TableStyle([("BACKGROUND", (0, 0), (-1, -1), PANEL),
                                  ("LINEBEFORE", (0, 0), (0, -1), 2, NAVY_2),
                                  ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                                  ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]),
            )
            block: list[Flowable] = [KeepTogether([
                head, Spacer(1, 4), meta, self.para("FINDING", "label"), self.para(_t(f.description)),
                Spacer(1, 6), attack,
            ])]
            if f.evidence:
                block.append(self.para("EVIDENCE", "label"))
                block += [self.para(line, "evidence") for line in _evidence_lines(f.evidence)]
            block.append(self.para("REMEDIATION · REVIEW BEFORE RUNNING", "label"))
            code_rows = [[self.para(_t(line) or "&nbsp;", "codecomment" if line.lstrip().startswith("#") else "code")]
                         for line in f.remediation_cli.splitlines()]
            block.append(Table(code_rows, colWidths=[CONTENT_W], style=TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
                ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
                ("TOPPADDING", (0, 0), (-1, 0), 6), ("BOTTOMPADDING", (0, -1), (-1, -1), 6),
            ])))
            block.append(Spacer(1, 16))
            out += [CondPageBreak(45 * mm), *block]
        return out

    def inventory(self) -> list[Flowable]:
        out = self.h1("Non-human identity inventory",
                      f"All {len(self.p.entities)} identities in scope, as observed at scan time.")
        rows = []
        for e in self.p.entities:
            fs = self.by_entity.get(e.entity_id, [])
            worst = self.worst(fs)
            owner = (f"<font color='{_hex(SEV_COLOR[Severity.CRITICAL])}'><b>Orphaned</b></font>" if e.is_orphaned
                     else _t(_owners_label(e.owners) or "n/a (by design)"))
            no_local_sp = e.entity_type is EntityType.APP_REGISTRATION and not e.raw_metadata.get("service_principal_id")
            last = "n/a" if not self.signins_known or no_local_sp else (_date(e.last_sign_in) if e.last_sign_in else "Never")
            sev_text = (f"<font color='{_hex(SEV_COLOR[worst])}'><b>{len(fs)} · {worst.value}</b></font>"
                        if worst else f"<font color='#079455'>0</font>")
            rows.append([
                self.para(f"{_t(e.display_name)}<br/><font size=6 color='{_hex(MUTED)}'>"
                          f"{_t(e.app_id or e.entity_id)}</font>", "cell"),
                self.para(TYPE_LABEL[e.entity_type], "cell"),
                self.para(owner, "cell"),
                self.para(_t(last), "cell"),
                self.para("Enabled" if e.is_enabled else "Disabled", "cell"),
                self.para(sev_text, "cell"),
            ])
        w = CONTENT_W
        out.append(self.data_table(["Identity", "Type", "Owner(s)", "Last sign-in", "Status", "Findings"], rows,
                                   [w * 0.27, w * 0.14, w * 0.28, w * 0.12, w * 0.08, w * 0.11]))
        return out

    def methodology(self) -> list[Flowable]:
        md = self.md
        out = self.h1("Methodology & coverage", "How the data was collected, which checks ran and how to read the score.")
        out.append(self.para("Approach", "h2"))
        out.append(self.para(
            "zetah-scanner performs a <b>read-only</b> collection through Microsoft Graph and Azure Resource "
            "Manager. No configuration is changed and no credential values are read: only credential metadata "
            "(identifiers, display names, validity dates). Each rule emits at most one finding per identity, "
            "aggregating every instance it found into the evidence, so the finding ID stays stable across scans."
        ))

        out.append(self.para("Data sources", "h2"))
        ok = "<font color='#079455'><b>Collected</b></font>"
        ko = f"<font color='{_hex(SEV_COLOR[Severity.HIGH])}'><b>Not available</b></font>"
        src_rows = [
            [self.para("Microsoft Graph · directory", "cellb"),
             self.para("App registrations, service principals, owners, credential metadata", "cell"),
             self.para(ok, "cell")],
            [self.para("Microsoft Graph · permissions", "cellb"),
             self.para("Application permissions on Microsoft Graph", "cell"),
             self.para(ok if self.permissions_known else ko, "cell")],
            [self.para("Microsoft Graph · roles", "cellb"),
             self.para("Entra directory role assignments, directly to service principals", "cell"),
             self.para(ok if self.roles_known else ko, "cell")],
            [self.para("Microsoft Graph · sign-in activity", "cellb"),
             self.para("Last sign-in per service principal (servicePrincipalSignInActivities; requires "
                       "AuditLog.Read.All and Entra ID P1)", "cell"),
             self.para(ok if self.signins_known else ko, "cell")],
            [self.para("Azure Resource Manager", "cellb"),
             self.para("Role assignments to service principals and managed identities across subscriptions",
                       "cell"), self.para(ok if self.azure_known else ko, "cell")],
        ]
        w = CONTENT_W
        out.append(self.data_table(["Source", "What it provides", "Status"], src_rows, [w * 0.28, w * 0.54, w * 0.18]))
        if md.collection_warnings:
            out.append(self.para("Collection warnings", "h2"))
            for warn in md.collection_warnings:
                out.append(self.para(f"• {_t(warn)}", "bullet"))

        out.append(self.para("Checks performed", "h2"))
        evaluated = set(md.rules_evaluated)
        hits = Counter(f.rule_id for f in self.p.findings)
        rule_rows = []
        for r in RULES:
            if r.rule_id in evaluated:
                status = (f"<font color='{_hex(SEV_COLOR[Severity.CRITICAL])}'><b>{hits[r.rule_id]} finding"
                          f"{'s' if hits[r.rule_id] != 1 else ''}</b></font>" if hits[r.rule_id]
                          else "<font color='#079455'><b>Pass</b></font>")
            else:
                status = f"<font color='{_hex(MUTED)}'>{_t(REQUIREMENT_LABEL.get(r.requires or '', 'Skipped'))}</font>"
            rule_rows.append([
                self.para(_t(r.rule_id), "cellb"), self.para(CATEGORY_LABEL[r.category], "cell"),
                self.para(_t(r.title), "cell"), self.para(status, "cell"),
            ])
        out.append(self.data_table(["Rule", "Category", "Check", "Result"], rule_rows,
                                   [w * 0.17, w * 0.25, w * 0.34, w * 0.24]))

        out.append(self.para("Hygiene score", "h2"))
        caps = ", ".join(f"{sev.value.lower()} up to {int(cap)}" for sev, (_each, cap) in SCORE_PENALTIES.items())
        out.append(self.para(
            "The score starts at 100. Each severity removes points with diminishing returns, up to a cap "
            f"({caps} points), so a tenant with many issues is not simply stuck at zero and fixing them raises "
            "the score. The score is a whole number: with many findings of the same severity, several fixes may "
            "be needed before it moves by one point, and the finding counts in this report are the exact measure "
            f"of progress. Any open critical finding caps the score at {CRITICAL_CEILING}. Bands: 80-100 <b>Good</b>, "
            "50-79 <b>Needs attention</b>, 0-49 <b>At risk</b>."
        ))
        out.append(self.para("Severity and priority", "h2"))
        sev_rows = [
            [self.badge(Severity.CRITICAL), self.para("P1 · immediately", "cellb"),
             self.para("Direct path to tenant or Azure takeover, data exfiltration by an AI agent, or a likely "
                       "persistence mechanism.", "cell")],
            [self.badge(Severity.HIGH), self.para("P2 · within 30 days", "cellb"),
             self.para("Tenant-wide data access, privileged roles, or weaknesses on privileged identities.", "cell")],
            [self.badge(Severity.MEDIUM), self.para("P3 · within 90 days", "cellb"),
             self.para("Hygiene gaps that enlarge the attack surface or slow incident response.", "cell")],
            [self.badge(Severity.LOW), self.para("P4 · next review", "cellb"),
             self.para("Housekeeping and operational risk.", "cell")],
        ]
        out.append(self.data_table(["Severity", "Priority", "Meaning"], sev_rows, [w * 0.17, w * 0.23, w * 0.60],
                                   zebra=False))
        out.append(self.para("Limitations", "h2"))
        for text in (
            "This is a point-in-time assessment; identities and permissions change continuously.",
            "A clean result covers only the checks listed in this report: it does not prove that an identity is "
            "harmless.",
            "Only application permissions on Microsoft Graph are evaluated. Permissions on other APIs, such as "
            "Exchange Online full_access_as_app or SharePoint Online, are not read.",
            "Entra roles held through role-assignable groups, Azure roles held through groups, and custom Azure "
            "roles equivalent to Owner or Contributor are not evaluated.",
            "AI agents are recognised from Entra Agent ID objects, agent tags and naming patterns. Naming-based "
            "classification is heuristic: generic names such as 'agent' or 'bot' count only next to an AI term, so "
            "unlabelled agents may be missing. The matched signals are recorded for every agent.",
            "An app registration and its service principal are separate objects in Entra and are listed as two "
            "identities, so identity counts are higher than the number of applications.",
            "Delegated (user-consented) permissions, Conditional Access for workload identities, federated "
            "credentials and activity inside other tenants are out of scope for this version.",
            "Sign-in activity is recorded per application, not per credential, and only covers sign-ins into this "
            "tenant; multi-tenant apps are excluded from dormancy checks for that reason.",
            "Only the Microsoft global cloud is supported.",
        ):
            out.append(self.para(f"• {_t(text)}", "bullet"))
        out.append(Spacer(1, 10))
        out.append(self.para(
            f"Generated by zetah-scanner {__version__} on {_date(self.generated, with_time=True)} · "
            f"scan {md.scan_id}", "tiny"))
        return out

    # ---- assembly ---------------------------------------------------------- #

    def build(self, path: Path) -> None:
        doc = _Doc(
            str(path), pagesize=A4,
            leftMargin=MARGIN, rightMargin=MARGIN, topMargin=18 * mm, bottomMargin=18 * mm,
            title=f"NHI Security Assessment - {self.org}",
            author="zetah-scanner (Zetah)",
            subject=f"Non-human identity security assessment, scan {self.md.scan_id}",
            creator=f"zetah-scanner {__version__}",
        )
        frame = Frame(MARGIN, 18 * mm, CONTENT_W, PAGE_H - 36 * mm, id="body",
                      leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
        doc.addPageTemplates([
            PageTemplate(id="cover", frames=[frame], onPage=self.draw_cover),
            PageTemplate(id="body", frames=[frame]),
        ])
        story: list[Flowable] = [NextPageTemplate("body"), Spacer(1, 1), PageBreak()]
        for section in (self.executive_summary, self.agent_id_readiness, self.risk_overview, self.remediation_plan,
                        self.detailed_findings, self.inventory, self.methodology):
            story += section()
            story.append(PageBreak())
        story.pop()
        doc.build(story, canvasmaker=functools.partial(_NumberedCanvas, decorate=self.decorate))


def write_pdf_report(payload: ZetahScanPayload, path: Path, org_name: Optional[str] = None) -> Path:
    _Report(payload, org_name or payload.metadata.tenant_id).build(path)
    return path

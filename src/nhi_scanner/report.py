"""Terminal rendering of a ``ZetahScanPayload`` with rich."""

from __future__ import annotations

from datetime import datetime, timezone

from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import EntityType, Severity, ZetahScanPayload

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}
TYPE_LABEL = {
    EntityType.SERVICE_PRINCIPAL: "Service principal",
    EntityType.APP_REGISTRATION: "App registration",
    EntityType.MANAGED_IDENTITY: "Managed identity",
    EntityType.AI_AGENT: "AI agent",
}


def _score_style(score: int) -> str:
    return "bold green" if score >= 80 else "bold yellow" if score >= 50 else "bold red"


def _ago(dt: datetime | None) -> str:
    if dt is None:
        return "[dim]never[/]"
    days = (datetime.now(timezone.utc) - dt).days
    return "today" if days == 0 else f"{days}d ago"


def render(payload: ZetahScanPayload, console: Console, tenant_name: str | None = None) -> None:
    md = payload.metadata
    sc = md.summary_counts

    sev = Text.assemble(
        *[(f" {n} {s.value} ", SEVERITY_STYLE[s]) for s, n in (
            (Severity.CRITICAL, sc.by_severity.critical), (Severity.HIGH, sc.by_severity.high),
            (Severity.MEDIUM, sc.by_severity.medium), (Severity.LOW, sc.by_severity.low))],
    )
    header = Table.grid(padding=(0, 2))
    header.add_column(style="dim")
    header.add_column()
    # Names come from the tenant, where anyone can register an app: never let rich read them as markup
    header.add_row("Tenant", f"{escape(tenant_name or md.tenant_id)}  [dim]({escape(md.tenant_id)})[/]")
    header.add_row("Scan ID", str(md.scan_id))
    header.add_row("Hygiene score", Text(f"{md.hygiene_score}/100", style=_score_style(md.hygiene_score)))
    header.add_row("Findings", sev)
    header.add_row(
        "Identities",
        f"{sc.total_entities} total · {sc.by_entity_type.app_registration} app regs · "
        f"{sc.by_entity_type.service_principal} SPs · {sc.by_entity_type.managed_identity} MIs · "
        f"{sc.by_entity_type.ai_agent} AI agents · [bold red]{sc.orphaned_identities} orphaned[/]",
    )
    console.print(Panel(header, title="[bold]Zetah · Entra NHI scan[/]", border_style="magenta"))

    for w in md.collection_warnings:
        console.print(f"[yellow]⚠ {escape(w)}[/]")

    ent = Table(title="Non-human identity inventory", title_justify="left", expand=True)
    ent.add_column("Identity", overflow="fold")
    ent.add_column("Type")
    ent.add_column("Owners", overflow="fold")
    ent.add_column("Last sign-in", justify="right")
    ent.add_column("Findings", justify="right")
    signins_known = any(r.startswith("NHI-DORM") for r in md.rules_evaluated)
    per_entity: dict[str, list[Severity]] = {}
    for f in payload.findings:
        per_entity.setdefault(f.entity_id, []).append(f.severity)
    for e in payload.entities:
        sevs = per_entity.get(e.entity_id, [])
        worst = max(sevs, key=lambda s: s.rank) if sevs else None
        owners = "[bold red]ORPHANED[/]" if e.is_orphaned else (escape(", ".join(e.owners)) or "[dim]n/a (by design)[/]")
        no_local_sp = e.entity_type is EntityType.APP_REGISTRATION and not e.raw_metadata.get("service_principal_id")
        ent.add_row(
            escape(e.display_name) + ("" if e.is_enabled else " [dim](disabled)[/]"),
            TYPE_LABEL[e.entity_type],
            owners,
            "[dim]n/a[/]" if not signins_known or no_local_sp else _ago(e.last_sign_in),
            Text(str(len(sevs)), style=SEVERITY_STYLE[worst]) if worst else Text("0", style="green"),
        )
    console.print(ent)

    if not payload.findings:
        console.print("[bold green]No findings. Clean tenant.[/]")
        return

    fnd = Table(title="Security findings", title_justify="left", expand=True, show_lines=True)
    fnd.add_column("Severity", no_wrap=True)
    fnd.add_column("Rule", no_wrap=True)
    fnd.add_column("Identity", overflow="fold")
    fnd.add_column("Finding / attack path", overflow="fold", ratio=3)
    for f in payload.findings:
        fnd.add_row(
            Text(f.severity.value, style=SEVERITY_STYLE[f.severity]),
            f.rule_id,
            escape(f.entity_name),
            Group(Text(f.title, style="bold"), Text(f.attack_path_context, style="dim")),
        )
    console.print(fnd)

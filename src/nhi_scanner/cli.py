"""zetah-scanner command line.

    python -m src.nhi_scanner.cli --demo --pdf report.pdf
    python -m src.nhi_scanner.cli --demo --json scan.json
    python -m src.nhi_scanner.cli --from-json scan.json --pdf report.pdf --org-name "Contoso"
    python -m src.nhi_scanner.cli --tenant-id <GUID> --json scan.json --pdf report.pdf
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.markup import escape

from . import __version__
from .engine import run_scan
from .models import Severity, ZetahScanPayload
from .readiness import agent_readiness
from .rules import RuleConfig


SIGN_IN_HELP = (
    "Could not sign in to Microsoft Entra. Run `az login --tenant <TENANT_GUID>` first, or set AZURE_TENANT_ID, "
    "AZURE_CLIENT_ID and AZURE_CLIENT_SECRET, then try again."
)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="zetah-scanner",
        description="Read-only Entra Agent ID readiness check: inventory and risk-score non-human identities.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--demo", action="store_true", help="scan a synthetic tenant instead of a real one")
    p.add_argument("--tenant-id", help="Entra tenant to scan (default: the credential's home tenant)")
    p.add_argument("--skip-azure-rbac", action="store_true", help="do not read Azure RBAC role assignments")
    p.add_argument("--dormant-days", type=int, default=90, help="inactivity threshold for dormancy rules (default 90)")
    p.add_argument("--json", metavar="PATH", type=Path, help="write the validated ZetahScanPayload to PATH")
    p.add_argument("--pdf", metavar="PATH", type=Path, help="write the executive PDF report to PATH")
    p.add_argument("--from-json", metavar="PATH", type=Path,
                   help="load a saved ZetahScanPayload instead of scanning (e.g. to re-render the PDF)")
    p.add_argument("--org-name", help="organization name shown in reports (default: the tenant display name)")
    p.add_argument("--schema-out", metavar="PATH", type=Path, help="write the ZetahScanPayload JSON Schema to PATH")
    p.add_argument("--quiet", action="store_true", help="no tables, only status lines")
    p.add_argument(
        "--fail-on", choices=[s.value.lower() for s in Severity],
        help="exit with code 2 if any finding is at or above this severity (CI gating)",
    )
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = _parser().parse_args(argv)
    console = Console()
    err = Console(stderr=True)

    if args.schema_out:
        args.schema_out.write_text(
            json.dumps(ZetahScanPayload.model_json_schema(mode="serialization"), indent=2), encoding="utf-8"
        )
        console.print(f"[green]✓[/] JSON Schema written to {args.schema_out}")
        if not (args.demo or args.tenant_id or args.json or args.pdf or args.from_json):
            return 0

    if args.from_json:
        if args.demo or args.tenant_id:
            err.print("[red]✗ --from-json cannot be combined with --demo or --tenant-id[/]")
            return 1
        try:
            payload = ZetahScanPayload.model_validate_json(args.from_json.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            err.print(f"[red]✗ {escape(str(args.from_json))} is not a valid ZetahScanPayload: {escape(str(exc))}[/]")
            return 1
        org_name = args.org_name or payload.metadata.tenant_id
    else:
        cfg = RuleConfig(dormant_days=args.dormant_days)
        with console.status("[bold magenta]Collecting tenant data…[/]") as status:
            if args.demo:
                from .demo import build_demo_snapshot
                snap = build_demo_snapshot()
            else:
                from azure.core.exceptions import ClientAuthenticationError

                from .collector import CollectionError, collect
                try:
                    snap = collect(
                        tenant_id=args.tenant_id,
                        include_azure_rbac=not args.skip_azure_rbac,
                        progress=lambda msg: status.update(f"[bold magenta]Collecting: {msg}…[/]"),
                    )
                except ClientAuthenticationError:
                    err.print(f"[red]✗ {SIGN_IN_HELP}[/]")
                    return 1
                except CollectionError as exc:
                    err.print(f"[red]✗ Collection failed: {escape(str(exc))}[/]")
                    return 1
                except Exception as exc:  # noqa: BLE001 — a scan must end with a message, not a traceback
                    err.print(f"[red]✗ Scan failed: {escape(str(exc))}[/]")
                    return 1
            status.update("[bold magenta]Evaluating rules…[/]")
            payload = run_scan(snap, cfg)
        org_name = args.org_name or snap.tenant_name

    if not args.quiet:
        from .report import render
        render(payload, console, org_name)

    ready = agent_readiness(payload)
    if ready.agents or not ready.agent_id_readable:
        on_agent_id = ready.count("agent_id") if ready.agent_id_readable else "unknown"
        console.print(
            f"[bold]Entra Agent ID readiness:[/] {len(ready.agents)} AI agents · {on_agent_id} on Agent ID · "
            f"{ready.count('legacy')} outside Agent ID · {ready.unaccountable} with nobody accountable"
            + (f" · {ready.unknown} unknown" if ready.unknown else "")
        )

    if args.json:
        args.json.write_text(payload.model_dump_json(indent=2) + "\n", encoding="utf-8")
        console.print(f"[green]✓[/] ZetahScanPayload written to {args.json} "
                      f"([dim]{len(payload.entities)} entities, {len(payload.findings)} findings[/])")

    if args.pdf:
        from .pdf_report import write_pdf_report
        with console.status("[bold magenta]Rendering PDF report…[/]"):
            write_pdf_report(payload, args.pdf, org_name)
        console.print(f"[green]✓[/] PDF report written to {args.pdf}")

    if args.fail_on:
        threshold = Severity(args.fail_on.upper()).rank
        if any(f.severity.rank >= threshold for f in payload.findings):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

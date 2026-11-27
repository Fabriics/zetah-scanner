"""Scan pipeline: TenantSnapshot -> inventory -> rules -> validated ZetahScanPayload."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

from .inventory import build_inventory
from .models import CONTRACT_VERSION, ScanMetadata, SecurityFinding, Severity, SummaryCounts, ZetahScanPayload
from .rules import RuleConfig, build_context, run_rules
from .snapshot import TenantSnapshot

# (weight per finding, most points the severity can cost in total). Each
# severity's penalty approaches its cap hyperbolically (cap * x / (x + cap)), so
# the score stays explainable ("criticals cost up to 60 points") without
# saturating after a handful of findings. The high cap is close to the critical
# one on purpose: a handful of high findings is never "Good" (5 -> 77) and many
# of them reach "At risk" (80 -> 49). The score is an integer, so with many
# findings of one severity a single fix can move it by less than a point:
# finding counts are the exact progress measure, and the report says so.
SCORE_PENALTIES: dict[Severity, tuple[float, float]] = {
    Severity.CRITICAL: (25, 60),
    Severity.HIGH: (8, 55),
    Severity.MEDIUM: (3, 15),
    Severity.LOW: (1, 5),
}
# A single tenant-takeover path keeps the score out of the "healthy" band.
CRITICAL_CEILING = 74


def hygiene_score(findings: list[SecurityFinding]) -> int:
    penalty = 0.0
    for sev, (each, cap) in SCORE_PENALTIES.items():
        x = each * sum(f.severity is sev for f in findings)
        penalty += cap * x / (x + cap)
    score = round(100 - penalty)
    if any(f.severity is Severity.CRITICAL for f in findings):
        score = min(score, CRITICAL_CEILING)
    return max(0, min(100, score))


def run_scan(
    snap: TenantSnapshot,
    cfg: Optional[RuleConfig] = None,
    now: Optional[datetime] = None,
) -> ZetahScanPayload:
    now = now or datetime.now(timezone.utc)
    inv = build_inventory(snap)
    ctx = build_context(snap, inv, cfg or RuleConfig(), now)
    findings, evaluated = run_rules(ctx)
    entities = sorted(inv.entities, key=lambda e: (e.entity_type.value, e.display_name.lower()))

    payload = ZetahScanPayload(
        metadata=ScanMetadata(
            contract_version=CONTRACT_VERSION,
            tenant_id=snap.tenant_id,
            scan_timestamp=now,
            hygiene_score=hygiene_score(findings),
            summary_counts=SummaryCounts.from_inventory(entities, findings),
            rules_evaluated=evaluated,
            collection_warnings=snap.warnings,
        ),
        entities=entities,
        findings=findings,
    )
    # What leaves the scanner must re-validate from its own JSON, byte for byte. Each part is checked on its own (the
    # payload-level checks ran when it was built): re-reading the whole payload at once would hold a second, larger
    # copy of it, several GB on a tenant of 100,000 identities.
    for part in [payload.metadata, *payload.entities, *payload.findings]:
        _round_trip(part)
    return payload


def _round_trip(model: BaseModel) -> None:
    data = model.model_dump_json()
    if type(model).model_validate_json(data).model_dump_json() != data:
        raise ValueError(f"{type(model).__name__} does not read back from its own JSON")


def write_payload_json(payload: ZetahScanPayload, path: Path) -> None:
    """The payload as ``model_dump_json(indent=2)`` writes it, byte for byte, one part at a time.

    Building the whole string first costs about four times the file in memory: 2 GB for the 520 MB payload of a
    tenant of 100,000 identities. Each part here is serialised with the same indent and shifted to its depth.
    """
    def part(model: BaseModel, depth: int) -> str:
        return model.model_dump_json(indent=2).replace("\n", "\n" + " " * depth)

    with path.open("w", encoding="utf-8") as out:
        out.write('{\n  "metadata": ' + part(payload.metadata, 2))
        for name, items in (("entities", payload.entities), ("findings", payload.findings)):
            out.write(f',\n  "{name}": ')
            if not items:
                out.write("[]")
                continue
            out.write("[\n")
            for i, item in enumerate(items):
                out.write(("    " if i == 0 else ",\n    ") + part(item, 4))
            out.write("\n  ]")
        out.write("\n}\n")

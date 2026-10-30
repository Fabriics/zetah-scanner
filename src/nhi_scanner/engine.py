"""Scan pipeline: TenantSnapshot -> inventory -> rules -> validated ZetahScanPayload."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .inventory import build_inventory
from .models import ScanMetadata, SecurityFinding, Severity, SummaryCounts, ZetahScanPayload
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
    # What leaves the scanner must re-validate from its own JSON, byte for byte.
    return ZetahScanPayload.model_validate_json(payload.model_dump_json())

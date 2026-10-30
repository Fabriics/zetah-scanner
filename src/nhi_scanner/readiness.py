"""Entra Agent ID readiness: where the tenant's AI agents stand before (or while) adopting Agent ID.

Derived from the scan payload only, so it adds nothing to the data contract: which agents already are
Agent ID identities, which still run as ordinary app registrations, service principals or managed
identities, whether a person is accountable for each, and which to bring under governance first.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

from .models import EntityType, NHIEntity, SecurityFinding, Severity, ZetahScanPayload
from .snapshot import AGENT_ID_UNREADABLE

AgentKind = Literal["agent_id", "blueprint", "legacy"]


@dataclass(frozen=True)
class AgentRow:
    entity: NHIEntity
    kind: AgentKind
    findings: tuple[SecurityFinding, ...]
    # True: an owner or sponsor is recorded; False: nobody; None: sponsors could not be read
    accountable: Optional[bool]

    @property
    def worst(self) -> Optional[Severity]:
        return max((f.severity for f in self.findings), key=lambda s: s.rank, default=None)

    @property
    def risk(self) -> tuple[int, int]:
        return (self.worst.rank if self.worst else 0, len(self.findings))


@dataclass(frozen=True)
class AgentReadiness:
    agents: tuple[AgentRow, ...]
    # False when Agent ID identities could not be listed: their count is then unknown, not zero
    agent_id_readable: bool = True

    def count(self, kind: AgentKind) -> int:
        return sum(a.kind == kind for a in self.agents)

    @property
    def accountable(self) -> int:
        return sum(a.accountable is True for a in self.agents)

    @property
    def unaccountable(self) -> int:
        return sum(a.accountable is False for a in self.agents)

    @property
    def unknown(self) -> int:
        return sum(a.accountable is None for a in self.agents)

    def govern_first(self, limit: int = 8) -> list[AgentRow]:
        """Agents outside Agent ID with open findings, riskiest first."""
        rows = [a for a in self.agents if a.kind == "legacy" and a.findings]
        return sorted(rows, key=lambda a: a.risk, reverse=True)[:limit]


def _kind(entity: NHIEntity) -> AgentKind:
    signals = entity.raw_metadata.get("agent_classification_signals") or []
    if "entra_agent_id" in signals:
        return "agent_id"
    if "entra_agent_blueprint" in signals:
        return "blueprint"
    return "legacy"


def agent_readiness(payload: ZetahScanPayload) -> AgentReadiness:
    by_entity: dict[str, list[SecurityFinding]] = {}
    for f in payload.findings:
        by_entity.setdefault(f.entity_id, []).append(f)
    rows = []
    for e in payload.entities:
        if e.entity_type is not EntityType.AI_AGENT:
            continue
        accountable = True if e.owners else None if e.raw_metadata.get("sponsors_unknown") else False
        rows.append(AgentRow(e, _kind(e), tuple(by_entity.get(e.entity_id, [])), accountable))
    readable = not any(w.startswith(AGENT_ID_UNREADABLE) for w in payload.metadata.collection_warnings)
    return AgentReadiness(tuple(rows), readable)

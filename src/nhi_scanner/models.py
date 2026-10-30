"""Data contract of a scan.

Every scan — real or ``--demo`` — is materialised as a ``ZetahScanPayload`` and
validated here before it is written to disk.
"""

from __future__ import annotations

import hashlib
import uuid
from collections import Counter
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Optional

from pydantic import (
    UUID4,
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    PlainSerializer,
    StringConstraints,
    model_validator,
)

from . import __version__


def _to_utc(value: datetime) -> datetime:
    return value.astimezone(timezone.utc)


# ISO 8601, always UTC, always serialised with a trailing "Z".
UTCDateTime = Annotated[
    AwareDatetime,
    AfterValidator(_to_utc),
    PlainSerializer(lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ"), return_type=str, when_used="json"),
]
NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
RuleId = Annotated[str, StringConstraints(pattern=r"^NHI-[A-Z]+-\d{3}$")]


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class EntityType(str, Enum):
    SERVICE_PRINCIPAL = "service_principal"
    APP_REGISTRATION = "app_registration"
    MANAGED_IDENTITY = "managed_identity"
    AI_AGENT = "ai_agent"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1}


class FindingCategory(str, Enum):
    SECRET_HYGIENE = "secret_hygiene"
    DORMANT_NHI = "dormant_nhi"
    EXCESSIVE_GRAPH_PERMISSIONS = "excessive_graph_permissions"
    AZURE_RBAC_PRIVILEGE = "azure_rbac_privilege"
    AI_AGENT_GOVERNANCE = "ai_agent_governance"


class SeverityCounts(_Contract):
    critical: int = Field(0, ge=0)
    high: int = Field(0, ge=0)
    medium: int = Field(0, ge=0)
    low: int = Field(0, ge=0)


class EntityTypeCounts(_Contract):
    service_principal: int = Field(0, ge=0)
    app_registration: int = Field(0, ge=0)
    managed_identity: int = Field(0, ge=0)
    ai_agent: int = Field(0, ge=0)


class SummaryCounts(_Contract):
    by_severity: SeverityCounts
    by_entity_type: EntityTypeCounts
    total_entities: int = Field(ge=0)
    total_findings: int = Field(ge=0)
    orphaned_identities: int = Field(ge=0)

    @classmethod
    def from_inventory(cls, entities: list[NHIEntity], findings: list[SecurityFinding]) -> SummaryCounts:
        sev = Counter(f.severity.value.lower() for f in findings)
        types = Counter(e.entity_type.value for e in entities)
        return cls(
            by_severity=SeverityCounts(**sev),
            by_entity_type=EntityTypeCounts(**types),
            total_entities=len(entities),
            total_findings=len(findings),
            orphaned_identities=sum(e.is_orphaned for e in entities),
        )


class ScanMetadata(_Contract):
    scan_id: UUID4 = Field(default_factory=uuid.uuid4)
    tenant_id: NonEmptyStr
    scan_timestamp: UTCDateTime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scanner_version: NonEmptyStr = __version__
    hygiene_score: int = Field(ge=0, le=100)
    summary_counts: SummaryCounts
    # Rules that actually ran in this scan. Zetah only auto-resolves open findings
    # whose rule was evaluated, so a scan that could not read sign-in logs or Azure
    # RBAC never "resolves" dormancy/RBAC issues by omission.
    rules_evaluated: list[RuleId] = Field(default_factory=list)
    collection_warnings: list[str] = Field(default_factory=list)


class NHIEntity(_Contract):
    entity_id: NonEmptyStr
    app_id: Optional[str] = None
    display_name: NonEmptyStr
    entity_type: EntityType
    created_datetime: Optional[UTCDateTime] = None
    last_sign_in: Optional[UTCDateTime] = None
    is_enabled: bool = True
    owners: list[str] = Field(default_factory=list)
    # Derived from ``owners``; always recomputed, never trusted from input.
    # Managed identities (bound to an Azure resource), Microsoft first-party service
    # principals and apps published by other organizations have no tenant owners by
    # design, so they never count.
    # Entra Agent ID identities whose sponsors could not be read are unknown, not orphaned.
    is_orphaned: bool = False
    raw_metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _derive_orphaned(self) -> NHIEntity:
        ownerless_by_design = (
            self.raw_metadata.get("servicePrincipalType") == "ManagedIdentity"
            or self.raw_metadata.get("is_microsoft_first_party") is True
            or self.raw_metadata.get("is_external_app") is True
            or self.raw_metadata.get("sponsors_unknown") is True
        )
        orphaned = not self.owners and not ownerless_by_design
        if self.is_orphaned != orphaned:
            # bypass validate_assignment to avoid re-entering this validator
            object.__setattr__(self, "is_orphaned", orphaned)
        return self


def compute_finding_id(tenant_id: str, entity_id: str, rule_id: str) -> str:
    """Deterministic across scans: same tenant + entity + rule => same finding."""
    return hashlib.sha256(f"{tenant_id}{entity_id}{rule_id}".encode()).hexdigest()


class SecurityFinding(_Contract):
    finding_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    rule_id: RuleId
    category: FindingCategory
    severity: Severity
    entity_id: NonEmptyStr
    entity_name: NonEmptyStr
    title: NonEmptyStr
    description: NonEmptyStr
    attack_path_context: NonEmptyStr
    remediation_cli: NonEmptyStr
    evidence: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def create(cls, *, tenant_id: str, entity: NHIEntity, rule_id: str, **fields: Any) -> SecurityFinding:
        return cls(
            finding_id=compute_finding_id(tenant_id, entity.entity_id, rule_id),
            rule_id=rule_id,
            entity_id=entity.entity_id,
            entity_name=entity.display_name,
            **fields,
        )


class ZetahScanPayload(_Contract):
    metadata: ScanMetadata
    entities: list[NHIEntity]
    findings: list[SecurityFinding]

    @model_validator(mode="after")
    def _check_integrity(self) -> ZetahScanPayload:
        entity_ids = [e.entity_id for e in self.entities]
        dupes = [k for k, n in Counter(entity_ids).items() if n > 1]
        if dupes:
            raise ValueError(f"duplicate entity_id(s): {dupes}")

        known = set(entity_ids)
        tenant = self.metadata.tenant_id
        seen: set[str] = set()
        for f in self.findings:
            if f.entity_id not in known:
                raise ValueError(f"finding {f.rule_id} references unknown entity {f.entity_id}")
            if f.finding_id != compute_finding_id(tenant, f.entity_id, f.rule_id):
                raise ValueError(f"finding_id mismatch for {f.rule_id} on {f.entity_id}")
            if f.finding_id in seen:
                raise ValueError(f"duplicate finding {f.rule_id} on {f.entity_id}")
            seen.add(f.finding_id)
            if self.metadata.rules_evaluated and f.rule_id not in self.metadata.rules_evaluated:
                raise ValueError(f"finding {f.rule_id} emitted by a rule not listed in rules_evaluated")

        expected = SummaryCounts.from_inventory(self.entities, self.findings)
        if self.metadata.summary_counts != expected:
            raise ValueError("metadata.summary_counts does not match entities/findings")
        return self

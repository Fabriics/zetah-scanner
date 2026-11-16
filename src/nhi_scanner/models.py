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
from typing import Annotated, Any, Literal, Optional

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

from . import __version__, owasp


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
# OWASP entries a finding is an instance of (see owasp.py): known codes only, no repeats, canonical order.
OwaspId = Literal[tuple(owasp.ENTRIES)]  # type: ignore[valid-type]  # the enum in the JSON Schema
OwaspIds = Annotated[list[OwaspId], Field(max_length=owasp.MAX_PER_FINDING), AfterValidator(owasp.check)]


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class EntityType(str, Enum):
    SERVICE_PRINCIPAL = "service_principal"
    APP_REGISTRATION = "app_registration"
    MANAGED_IDENTITY = "managed_identity"
    AI_AGENT = "ai_agent"
    # static keys that act as an identity for whoever holds them, e.g. the keys of an Azure OpenAI account
    API_KEY = "api_key"


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
    api_key: int = Field(0, ge=0)


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
    # Payloads written before the field existed (scanner 0.1.x) are version 1.
    contract_version: Literal[1, 2] = 1
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


# --------------------------------------------------------------------------- #
# Identity record (contract version 2)
#
# The record is the fact, the finding is the judgment: it describes every
# identity, clean ones included. Each section says where its data comes from,
# when it was read and whether it could be read at all, because "not read" is
# not "empty".
# --------------------------------------------------------------------------- #

CONTRACT_VERSION = 2


class SectionStatus(str, Enum):
    READ = "read"
    # could not be read, or was not collected in this scan: unknown, not empty
    NOT_READ = "not_read"
    # the section does not exist for this kind of identity
    NOT_APPLICABLE = "not_applicable"


class _Section(_Contract):
    status: SectionStatus
    # the API reads the data comes from, e.g. "GET /v1.0/servicePrincipals"
    sources: list[NonEmptyStr] = Field(default_factory=list)
    read_at: Optional[UTCDateTime] = None
    # coverage limits worth knowing even when status is "read"
    note: Optional[str] = None

    @model_validator(mode="after")
    def _status_is_consistent(self) -> _Section:
        if self.status is SectionStatus.READ and not (self.sources and self.read_at):
            raise ValueError("a section that was read must state its sources and read_at")
        if self.status is not SectionStatus.READ:
            for name in type(self).model_fields:
                if name in _Section.model_fields:
                    continue
                value = getattr(self, name)
                if value not in (None, [], ""):
                    raise ValueError(f"section is {self.status.value} but '{name}' holds data")
        return self


class ProfileSection(_Section):
    description: Optional[str] = None
    notes: Optional[str] = None
    sign_in_audience: Optional[str] = None
    publisher_domain: Optional[str] = None


class AccountableObjectType(str, Enum):
    USER = "user"
    SERVICE_PRINCIPAL = "service_principal"
    OTHER = "other"


class Accountable(_Contract):
    object_id: NonEmptyStr
    object_type: AccountableObjectType
    user_principal_name: Optional[str] = None
    display_name: Optional[str] = None
    # None when the account status could not be read
    account_enabled: Optional[bool] = None
    # where the owner is set: on the service principal or on its app registration
    held_on: Optional[Annotated[str, StringConstraints(pattern=r"^(application|service_principal)$")]] = None


class OwnersSection(_Section):
    items: list[Accountable] = Field(default_factory=list)


class SponsorsSection(_Section):
    items: list[Accountable] = Field(default_factory=list)


class CredentialKind(str, Enum):
    CLIENT_SECRET = "client_secret"
    CERTIFICATE = "certificate"
    API_KEY = "api_key"


class Credential(_Contract):
    """Credential metadata only: secret values are never read."""

    key_id: Optional[str] = None
    kind: CredentialKind
    display_name: Optional[str] = None
    start: Optional[UTCDateTime] = None
    end: Optional[UTCDateTime] = None
    held_on: Annotated[str, StringConstraints(pattern=r"^(application|service_principal|resource)$")]


class CredentialsSection(_Section):
    items: list[Credential] = Field(default_factory=list)


class FederatedCredential(_Contract):
    """Trust in an external identity provider (workload identity federation): no secret exists, but whoever can
    obtain a token from ``issuer`` with this ``subject`` signs in as the identity."""

    id: Optional[str] = None
    name: Optional[str] = None
    issuer: NonEmptyStr
    # None for a flexible credential, whose matching expression Microsoft Graph v1.0 does not return
    subject: Optional[str] = None
    audiences: list[str] = Field(default_factory=list)
    held_on: Annotated[str, StringConstraints(pattern=r"^(application|managed_identity)$")]


class FederatedCredentialsSection(_Section):
    items: list[FederatedCredential] = Field(default_factory=list)


class GraphPermission(_Contract):
    permission: NonEmptyStr
    assignment_id: NonEmptyStr


class GraphPermissionsSection(_Section):
    items: list[GraphPermission] = Field(default_factory=list)


class DelegatedPermission(_Contract):
    """A delegated permission (scope) consented to this client app: it acts as the signed-in user, within
    that user's own access."""

    resource: NonEmptyStr  # display name of the API, e.g. "Microsoft Graph"
    resource_id: NonEmptyStr  # object ID of the API's service principal
    scope: NonEmptyStr  # e.g. "Mail.Read", "offline_access"
    # an administrator consented for every user of the tenant (consentType "AllPrincipals")
    all_users: bool
    # users who consented for themselves (consentType "Principal")
    user_count: int = Field(ge=0)

    @model_validator(mode="after")
    def _someone_consented(self) -> DelegatedPermission:
        if not self.all_users and self.user_count == 0:
            raise ValueError("a delegated permission is consented for all users or for at least one user")
        return self


class DelegatedPermissionsSection(_Section):
    items: list[DelegatedPermission] = Field(default_factory=list)


class DirectoryRole(_Contract):
    role: NonEmptyStr
    role_template_id: Optional[str] = None
    directory_scope: NonEmptyStr = "/"
    assignment_id: NonEmptyStr


class DirectoryRolesSection(_Section):
    items: list[DirectoryRole] = Field(default_factory=list)


class AzureRole(_Contract):
    role: NonEmptyStr
    scope: NonEmptyStr
    assignment_id: NonEmptyStr


class AzureRolesSection(_Section):
    items: list[AzureRole] = Field(default_factory=list)


class ActivitySection(_Section):
    # None with status "read" means no sign-in was recorded
    last_sign_in: Optional[UTCDateTime] = None


class IdentityRecord(_Contract):
    profile: ProfileSection
    owners: OwnersSection
    sponsors: SponsorsSection
    credentials: CredentialsSection
    federated_credentials: FederatedCredentialsSection
    graph_permissions: GraphPermissionsSection
    delegated_permissions: DelegatedPermissionsSection
    directory_roles: DirectoryRolesSection
    azure_roles: AzureRolesSection
    activity: ActivitySection


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
    # Contract version 2: the full record of the identity. Absent in version 1 payloads.
    record: Optional[IdentityRecord] = None

    @model_validator(mode="after")
    def _derive_orphaned(self) -> NHIEntity:
        ownerless_by_design = (
            self.raw_metadata.get("servicePrincipalType") == "ManagedIdentity"
            or self.raw_metadata.get("is_microsoft_first_party") is True
            or self.raw_metadata.get("is_external_app") is True
            or self.raw_metadata.get("sponsors_unknown") is True
            or self.raw_metadata.get("is_azure_resource") is True  # Azure resources have no owner field
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
    # Contract version 2: set from the rule that emitted the finding, never by the finding itself.
    owasp: OwaspIds = Field(default_factory=list)

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

        with_record = sum(e.record is not None for e in self.entities)
        if self.metadata.contract_version >= 2 and with_record != len(self.entities):
            raise ValueError("contract version 2 requires a record on every entity")
        if self.metadata.contract_version == 1 and with_record:
            raise ValueError("contract version 1 payloads carry no identity record")
        if self.metadata.contract_version == 1 and any(f.owasp for f in self.findings):
            raise ValueError("contract version 1 payloads carry no OWASP mapping")

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

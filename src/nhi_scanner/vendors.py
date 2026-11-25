"""Third-party apps grouped by the vendor that holds their credentials.

An enterprise app published by another organization signs in with credentials that live in the publisher's tenant.
If that vendor is breached, every app it publishes here is exposed at once, so the question a CISO asks is per
vendor: "if this supplier falls, what can the attacker do in our tenant?". This view answers it from the payload
alone, so it works on a saved scan too.

It is the first door of the "if X falls" engine: the vendor is the key, the identities and their permissions are
what falls with it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models import NHIEntity, SecurityFinding, Severity, ZetahScanPayload

VENDOR_RULE = "NHI-PERM-004"
_SEVERITIES = {s.value: s for s in Severity}


def is_third_party(entity: NHIEntity) -> bool:
    """Published by another organization that is not Microsoft, and not a managed identity."""
    m = entity.raw_metadata
    return (m.get("is_external_app") is True and m.get("is_microsoft_first_party") is not True
            and m.get("servicePrincipalType") != "ManagedIdentity")


@dataclass(frozen=True)
class VendorPermission:
    api: str
    permission: str
    write: bool
    severity: Severity


@dataclass
class VendorApp:
    entity: NHIEntity
    # None when application permissions were not read in this scan; empty when the app holds none
    permissions: Optional[list[VendorPermission]]
    finding: Optional[SecurityFinding] = None
    # delegated consents: scopes, and whether an administrator consented for every user
    delegated_scopes: int = 0
    delegated_all_users: bool = False

    @property
    def writes(self) -> list[VendorPermission]:
        return [p for p in self.permissions or [] if p.write]


@dataclass
class Vendor:
    tenant_id: str
    publishers: list[str]
    apps: list[VendorApp] = field(default_factory=list)

    @property
    def worst(self) -> Optional[Severity]:
        return max((a.finding.severity for a in self.apps if a.finding), key=lambda s: s.rank, default=None)

    @property
    def write_count(self) -> int:
        return sum(len(a.writes) for a in self.apps)


def _permissions(finding: Optional[SecurityFinding]) -> list[VendorPermission]:
    """The permissions a finding lists, ignoring entries a tampered payload could carry in the wrong shape."""
    out = []
    raw = finding.evidence.get("permissions") if finding else None
    for p in raw if isinstance(raw, list) else []:
        if not isinstance(p, dict):
            continue
        api, name, sev = p.get("api"), p.get("permission"), _SEVERITIES.get(p.get("severity"))
        if isinstance(api, str) and isinstance(name, str) and api and name and sev:
            out.append(VendorPermission(api=api, permission=name, write=p.get("write") is True, severity=sev))
    return out


def vendor_view(payload: ZetahScanPayload) -> list[Vendor]:
    """Every third-party app in scope, grouped by its publisher's tenant, the most exposed vendor first."""
    findings = {f.entity_id: f for f in payload.findings if f.rule_id == VENDOR_RULE}
    permissions_read = VENDOR_RULE in payload.metadata.rules_evaluated
    vendors: dict[str, Vendor] = {}
    for e in payload.entities:
        if not is_third_party(e):
            continue
        tenant = str(e.raw_metadata.get("appOwnerOrganizationId") or "unknown")
        v = vendors.setdefault(tenant, Vendor(tenant_id=tenant, publishers=[]))
        publisher = e.raw_metadata.get("verifiedPublisher")
        if isinstance(publisher, str) and publisher and publisher not in v.publishers:
            v.publishers.append(publisher)
        f = findings.get(e.entity_id)
        consents = e.record.delegated_permissions.items if e.record else []
        v.apps.append(VendorApp(
            entity=e,
            permissions=_permissions(f) if permissions_read else None,
            finding=f,
            delegated_scopes=len(consents),
            delegated_all_users=any(c.all_users for c in consents),
        ))
    for v in vendors.values():
        v.publishers.sort()
        v.apps.sort(key=lambda a: (-(a.finding.severity.rank if a.finding else 0), a.entity.display_name))
    return sorted(vendors.values(), key=lambda v: (-(v.worst.rank if v.worst else 0), -v.write_count,
                                                   v.publishers[0] if v.publishers else "~", v.tenant_id))


def apps_exposed_if(payload: ZetahScanPayload, tenant_id: str) -> list[VendorApp]:
    """The apps that fall with a vendor's tenant, with what each one can do here."""
    return next((v.apps for v in vendor_view(payload) if v.tenant_id == tenant_id), [])


def summary_line(vendors: list[Vendor]) -> Optional[str]:
    if not vendors:
        return None
    apps = sum(len(v.apps) for v in vendors)
    exposed = [v for v in vendors if v.worst]
    writes = sum(v.write_count for v in vendors)
    return (f"{apps} third-party app(s) from {len(vendors)} vendor(s); {len(exposed)} vendor(s) hold tenant-wide "
            f"application permissions, with {writes} permission(s) that can write or send.")


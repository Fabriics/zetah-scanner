"""Raw tenant data, in Graph/ARM wire format, as collected (or synthesised by --demo).

Both the live collector and the demo dataset produce a ``TenantSnapshot``; from
there on, normalisation and rules are the same code path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

_FRACTION = re.compile(r"(\.\d{6})\d+")

# Start of the collection warning raised when Entra Agent ID identities cannot be listed.
AGENT_ID_UNREADABLE = "Entra Agent ID identities not read"

# The reads each part of a snapshot comes from. Identity records cite them as their sources.
SRC_APPLICATIONS = "GET /v1.0/applications"
SRC_SERVICE_PRINCIPALS = "GET /v1.0/servicePrincipals"
SRC_AGENT_IDENTITIES = "GET /v1.0/servicePrincipals/microsoft.graph.agentIdentity"
SRC_SPONSORS = "GET /v1.0/servicePrincipals/{id}/microsoft.graph.agentIdentity/sponsors"
SRC_GRAPH_PERMISSIONS = "GET /v1.0/servicePrincipals/{Microsoft Graph}/appRoleAssignedTo"
SRC_DELEGATED_GRANTS = "GET /v1.0/oauth2PermissionGrants"
SRC_DIRECTORY_ROLES = "GET /v1.0/roleManagement/directory/roleAssignments"
SRC_SIGNIN_ACTIVITY = "GET /beta/reports/servicePrincipalSignInActivities"
SRC_AZURE_RBAC = "GET ARM /subscriptions/{id}/providers/Microsoft.Authorization/roleAssignments"


def parse_graph_datetime(value: Optional[str]) -> Optional[datetime]:
    """Graph/ARM timestamps -> aware UTC datetime (handles 'Z' and 7-digit fractions)."""
    if not value:
        return None
    value = _FRACTION.sub(r"\1", value.replace("Z", "+00:00"))
    parsed = datetime.fromisoformat(value)
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def credential_metadata(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """Secrets and certificates of an application or service principal, normalised (metadata only)."""
    out = []
    for kind, key in (("client_secret", "passwordCredentials"), ("certificate", "keyCredentials")):
        for c in obj.get(key) or []:
            out.append({
                "kind": kind,
                "key_id": c.get("keyId"),
                "display_name": c.get("displayName") or "",
                "start": parse_graph_datetime(c.get("startDateTime")),
                "end": parse_graph_datetime(c.get("endDateTime")),
            })
    return out


@dataclass
class TenantSnapshot:
    tenant_id: str
    tenant_name: str
    collected_at: datetime
    # GET /applications (with owners expanded)
    applications: list[dict[str, Any]]
    # GET /servicePrincipals (with owners expanded)
    service_principals: list[dict[str, Any]]
    # GET /servicePrincipals/{msgraph}/appRoleAssignedTo — application permissions on Microsoft Graph.
    # None when they could not be read; the permission rules are then skipped.
    graph_app_role_assignments: Optional[list[dict[str, Any]]]
    # appRoleId -> permission value, from the Microsoft Graph service principal's appRoles
    graph_app_roles: dict[str, str]
    # GET /roleManagement/directory/roleAssignments. None when they could not be read;
    # the directory role rule is then skipped.
    directory_role_assignments: Optional[list[dict[str, Any]]]
    # roleDefinitionId -> {"displayName", "templateId"}
    directory_role_definitions: dict[str, dict[str, Any]]
    # appId -> last sign-in (None = never). The whole field is None when the
    # sign-in report could not be read; dormancy rules are then skipped.
    signin_activity: Optional[dict[str, Optional[datetime]]]
    # Flattened ARM role assignments to service principals:
    # {"id", "principalId", "roleName", "scope"}. None when Azure was not scanned.
    azure_role_assignments: Optional[list[dict[str, Any]]]
    warnings: list[str] = field(default_factory=list)
    # SRC_* -> when that read finished. Sources missing here fall back to ``collected_at``.
    read_at: dict[str, datetime] = field(default_factory=dict)
    # False when owners were read without their account status (accountEnabled)
    owner_status_read: bool = True
    # GET /oauth2PermissionGrants — delegated permissions consented to client apps, for all users
    # (consentType "AllPrincipals") or for one user ("Principal"). None when they could not be read;
    # the consent rules are then skipped.
    delegated_permission_grants: Optional[list[dict[str, Any]]] = None

    def read_time(self, source: str) -> datetime:
        return self.read_at.get(source, self.collected_at)

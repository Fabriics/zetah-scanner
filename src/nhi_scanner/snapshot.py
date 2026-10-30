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


def parse_graph_datetime(value: Optional[str]) -> Optional[datetime]:
    """Graph/ARM timestamps -> aware UTC datetime (handles 'Z' and 7-digit fractions)."""
    if not value:
        return None
    value = _FRACTION.sub(r"\1", value.replace("Z", "+00:00"))
    parsed = datetime.fromisoformat(value)
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


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

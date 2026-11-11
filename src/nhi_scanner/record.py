"""Build the identity record of each entity from a ``TenantSnapshot``.

The record is the fact, the finding is the judgment: it describes every
identity, clean ones included, with everything the scan read about it. Each
section names the reads it comes from and when they finished, and a section
that could not be read is marked ``not_read`` instead of looking empty.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

from .models import (
    Accountable,
    AccountableObjectType,
    ActivitySection,
    AzureRole,
    AzureRolesSection,
    Credential,
    CredentialsSection,
    DelegatedPermission,
    DelegatedPermissionsSection,
    FederatedCredential,
    FederatedCredentialsSection,
    DirectoryRole,
    DirectoryRolesSection,
    GraphPermission,
    GraphPermissionsSection,
    IdentityRecord,
    OwnersSection,
    ProfileSection,
    SectionStatus,
    SponsorsSection,
)
from .snapshot import (
    SRC_AGENT_IDENTITIES,
    SRC_AI_ACCOUNTS,
    SRC_APPLICATIONS,
    SRC_AZURE_RBAC,
    SRC_DELEGATED_GRANTS,
    SRC_DIRECTORY_ROLES,
    SRC_FEDERATED_APPS,
    SRC_FEDERATED_MI,
    SRC_GRAPH_PERMISSIONS,
    SRC_SERVICE_PRINCIPALS,
    SRC_SIGNIN_ACTIVITY,
    SRC_SPONSORS,
    TenantSnapshot,
    credential_metadata,
)

READ = SectionStatus.READ
NOT_READ = SectionStatus.NOT_READ
NOT_APPLICABLE = SectionStatus.NOT_APPLICABLE

_ON_SERVICE_PRINCIPAL = "Permissions and roles are granted to the service principal: see its record."
_OWNER_STATUS_NOT_READ = "Owner account status was not read in this scan."
_PROFILE_PARTIAL = "Description and notes were not read in this scan."


@dataclass
class RecordIndex:
    """Per-principal lookups over the snapshot, built once per scan."""

    graph_permissions: dict[str, list[GraphPermission]] = field(default_factory=dict)
    delegated_permissions: dict[str, list[DelegatedPermission]] = field(default_factory=dict)
    directory_roles: dict[str, list[DirectoryRole]] = field(default_factory=dict)
    azure_roles: dict[str, list[AzureRole]] = field(default_factory=dict)


def build_index(snap: TenantSnapshot) -> RecordIndex:
    perms: dict[str, list[GraphPermission]] = defaultdict(list)
    for a in snap.graph_app_role_assignments or []:
        # an app role Microsoft Graph no longer lists is still a grant: keep its id
        name = snap.graph_app_roles.get(a["appRoleId"]) or a["appRoleId"]
        perms[a["principalId"]].append(GraphPermission(permission=name, assignment_id=a["id"]))

    # client -> (resource, scope) -> [consented for all users, users who consented themselves]
    consents: dict[str, dict[tuple[str, str], list[Any]]] = defaultdict(dict)
    for g in snap.delegated_permission_grants or []:
        for scope in (g.get("scope") or "").split():
            entry = consents[g["clientId"]].setdefault((g["resourceId"], scope), [False, set()])
            if g.get("consentType") == "AllPrincipals":
                entry[0] = True
            elif g.get("principalId"):
                entry[1].add(g["principalId"])
    names = {sp["id"]: sp.get("displayName") or sp["id"] for sp in snap.service_principals}
    delegated = {
        client: [
            DelegatedPermission(resource=names.get(res, res), resource_id=res, scope=scope,
                                all_users=all_users, user_count=len(users))
            for (res, scope), (all_users, users) in per_scope.items()
            if all_users or users
        ]
        for client, per_scope in consents.items()
    }

    roles: dict[str, list[DirectoryRole]] = defaultdict(list)
    for a in snap.directory_role_assignments or []:
        rdef = snap.directory_role_definitions.get(a["roleDefinitionId"], {})
        roles[a["principalId"]].append(DirectoryRole(
            role=rdef.get("displayName") or a["roleDefinitionId"],
            role_template_id=rdef.get("templateId"),
            directory_scope=a.get("directoryScopeId") or "/",
            assignment_id=a["id"],
        ))

    azure: dict[str, list[AzureRole]] = defaultdict(list)
    for ra in snap.azure_role_assignments or []:
        azure[ra["principalId"]].append(AzureRole(role=ra["roleName"], scope=ra["scope"], assignment_id=ra["id"]))

    def ordered(d: dict[str, list[Any]], key: Any) -> dict[str, list[Any]]:
        return {k: sorted(v, key=key) for k, v in d.items()}

    return RecordIndex(
        graph_permissions=ordered(perms, lambda p: (p.permission, p.assignment_id)),
        delegated_permissions=ordered(delegated, lambda d: (d.resource, d.scope.lower())),
        directory_roles=ordered(roles, lambda r: (r.role, r.directory_scope, r.assignment_id)),
        azure_roles=ordered(azure, lambda r: (r.scope, r.role, r.assignment_id)),
    )


def _read(snap: TenantSnapshot, *sources: str) -> dict[str, Any]:
    """Provenance of a section that was read: its sources and the oldest of their read times."""
    return {"status": READ, "sources": list(sources), "read_at": min(snap.read_time(s) for s in sources)}


def _join(*notes: Optional[str]) -> Optional[str]:
    return " ".join(n for n in notes if n) or None


def _accountable(obj: dict[str, Any], held_on: Optional[str]) -> Accountable:
    odata = (obj.get("@odata.type") or "").lower()
    if odata.endswith("serviceprincipal") or odata.endswith("agentidentity"):
        kind = AccountableObjectType.SERVICE_PRINCIPAL
    elif odata.endswith("user") or obj.get("userPrincipalName"):
        kind = AccountableObjectType.USER
    else:
        kind = AccountableObjectType.OTHER
    enabled = obj.get("accountEnabled")
    return Accountable(
        object_id=obj["id"],
        object_type=kind,
        user_principal_name=obj.get("userPrincipalName"),
        display_name=obj.get("displayName"),
        account_enabled=enabled if isinstance(enabled, bool) else None,
        held_on=held_on,
    )


def _credentials(obj: dict[str, Any], held_on: str) -> list[Credential]:
    return [
        Credential(key_id=c["key_id"], kind=c["kind"], display_name=c["display_name"] or None,
                   start=c["start"], end=c["end"], held_on=held_on)
        for c in credential_metadata(obj)
    ]


def _federated(items: list[dict[str, Any]], held_on: str) -> list[FederatedCredential]:
    return [
        FederatedCredential(id=f.get("id"), name=f.get("name"), issuer=f.get("issuer") or "unknown",
                            subject=f.get("subject") or None, audiences=f.get("audiences") or [], held_on=held_on)
        for f in sorted(items, key=lambda f: (f.get("issuer") or "", f.get("subject") or "", f.get("name") or ""))
    ]


def _app_federation(snap: TenantSnapshot, app: dict[str, Any]) -> FederatedCredentialsSection:
    if snap.app_federated_credentials is None:
        return FederatedCredentialsSection(status=NOT_READ, note="Federated credentials of app registrations could not be read.")
    return FederatedCredentialsSection(**_read(snap, SRC_FEDERATED_APPS),
                                       items=_federated(snap.app_federated_credentials.get(app["id"], []), "application"))


def _activity(snap: TenantSnapshot, app_id: Optional[str], note: Optional[str] = None) -> ActivitySection:
    if snap.signin_activity is None:
        return ActivitySection(status=NOT_READ, note="The sign-in activity report could not be read in this scan.")
    return ActivitySection(**_read(snap, SRC_SIGNIN_ACTIVITY), last_sign_in=snap.signin_activity.get(app_id),
                           note=note)


def application_record(snap: TenantSnapshot, app: dict[str, Any], has_local_sp: bool) -> IdentityRecord:
    """Record of an app registration (application object)."""
    owner_note = None if snap.owner_status_read else _OWNER_STATUS_NOT_READ
    not_here = NOT_APPLICABLE, _ON_SERVICE_PRINCIPAL
    return IdentityRecord(
        profile=ProfileSection(
            **_read(snap, SRC_APPLICATIONS),
            description=app.get("description"),
            notes=app.get("notes"),
            sign_in_audience=app.get("signInAudience"),
            publisher_domain=app.get("publisherDomain"),
            note=None if snap.owner_status_read else _PROFILE_PARTIAL,
        ),
        owners=OwnersSection(**_read(snap, SRC_APPLICATIONS), note=owner_note,
                             items=[_accountable(o, "application") for o in app.get("owners") or []]),
        sponsors=SponsorsSection(status=NOT_APPLICABLE),
        credentials=CredentialsSection(**_read(snap, SRC_APPLICATIONS), items=_credentials(app, "application")),
        federated_credentials=_app_federation(snap, app),
        graph_permissions=GraphPermissionsSection(status=not_here[0], note=not_here[1]),
        delegated_permissions=DelegatedPermissionsSection(status=not_here[0], note=not_here[1]),
        directory_roles=DirectoryRolesSection(status=not_here[0], note=not_here[1]),
        azure_roles=AzureRolesSection(status=not_here[0], note=not_here[1]),
        activity=_activity(
            snap, app.get("appId"),
            None if has_local_sp else "No service principal in this tenant: it signs in to other tenants only.",
        ),
    )


def api_key_record(snap: TenantSnapshot, account: dict[str, Any]) -> IdentityRecord:
    """Record of an Azure OpenAI or AI Services account seen as what its keys are: a shared static identity."""
    na = lambda note: {"status": NOT_APPLICABLE, "note": note}  # noqa: E731
    keys_live = not account.get("disable_local_auth")
    reach = ("public network access enabled" if account.get("public_network_access") != "Disabled" else "public network access disabled")
    return IdentityRecord(
        profile=ProfileSection(**_read(snap, SRC_AI_ACCOUNTS),
                               description=f"{account.get('kind')} account in {account.get('location')}",
                               note=f"Endpoint {account.get('endpoint') or 'not stated'}; {reach}; "
                                    f"network default action {account.get('network_default_action') or 'not set'}."),
        owners=OwnersSection(**na("Azure resources have no owner field: accountability comes from tags or role assignments.")),
        sponsors=SponsorsSection(status=NOT_APPLICABLE),
        credentials=CredentialsSection(
            **_read(snap, SRC_AI_ACCOUNTS),
            items=[Credential(kind="api_key", display_name=k, held_on="resource") for k in ("key1", "key2")] if keys_live else [],
            note=("Two account keys accept requests while local authentication is enabled. Their values and age are never "
                  "read." if keys_live else "Local authentication is disabled: the account keys cannot authenticate."),
        ),
        federated_credentials=FederatedCredentialsSection(**na("Not applicable to resource keys.")),
        graph_permissions=GraphPermissionsSection(**na("Not applicable to resource keys.")),
        delegated_permissions=DelegatedPermissionsSection(**na("Not applicable to resource keys.")),
        directory_roles=DirectoryRolesSection(**na("Not applicable to resource keys.")),
        azure_roles=AzureRolesSection(**na("The identities that can read these keys are listed in the finding.")),
        activity=ActivitySection(status=NOT_READ, note="Key usage is in the account's diagnostic logs, which are not read."),
    )


def service_principal_record(
    snap: TenantSnapshot,
    sp: dict[str, Any],
    app: Optional[dict[str, Any]],
    index: RecordIndex,
    *,
    is_agent_id: bool,
    is_external_app: bool,
) -> IdentityRecord:
    """Record of a service principal: the identity that signs in and holds permissions and roles."""
    sp_source = SRC_AGENT_IDENTITIES if is_agent_id else SRC_SERVICE_PRINCIPALS
    directory = (sp_source, SRC_APPLICATIONS) if app else (sp_source,)
    is_managed_identity = sp.get("servicePrincipalType") == "ManagedIdentity"

    by_design = None
    if is_managed_identity:
        by_design = "A managed identity is bound to an Azure resource and has no owners by design."
    elif is_external_app:
        by_design = "Published by another organization: its owners and app credentials live in that tenant."
    owners = [_accountable(o, "service_principal") for o in sp.get("owners") or []]
    owners += [_accountable(o, "application") for o in (app or {}).get("owners") or []]

    if not is_agent_id:
        sponsors = SponsorsSection(status=NOT_APPLICABLE)
    elif "sponsors" in sp:
        sponsors = SponsorsSection(**_read(snap, SRC_SPONSORS), items=[_accountable(s, None) for s in sp["sponsors"]])
    else:
        sponsors = SponsorsSection(
            status=NOT_READ,
            note="Sponsors could not be read (Microsoft currently documents AgentIdentity.ReadWrite.All for this read).",
        )

    creds = _credentials(sp, "service_principal") + (_credentials(app, "application") if app else [])
    cred_note = None
    if is_managed_identity:
        cred_note = "Managed identity credentials are handled by Azure and never listed."
    elif is_external_app:
        cred_note = "Credentials on the publisher's app registration are not visible from this tenant."

    sp_id = sp["id"]
    user_assigned = any(n == "isExplicit=True" for n in sp.get("alternativeNames") or [])
    if app:
        federation = _app_federation(snap, app)
    elif is_managed_identity and not user_assigned:
        federation = FederatedCredentialsSection(
            status=NOT_APPLICABLE, note="Only user-assigned managed identities can hold federated credentials.")
    elif is_managed_identity:
        federation = (FederatedCredentialsSection(status=NOT_READ, note="Azure was not scanned or the identity could not be read.")
                      if snap.mi_federated_credentials is None else
                      FederatedCredentialsSection(**_read(snap, SRC_FEDERATED_MI),
                                                  items=_federated(snap.mi_federated_credentials.get(sp_id, []), "managed_identity")))
    elif is_agent_id:
        federation = FederatedCredentialsSection(
            status=NOT_READ, note="Agent ID identities authenticate through their blueprint, whose credentials are not read yet.")
    else:
        federation = FederatedCredentialsSection(
            status=NOT_APPLICABLE, note="Federated credentials live on the app registration, in the publisher's tenant.")

    if snap.graph_app_role_assignments is None:
        perms = GraphPermissionsSection(status=NOT_READ, note="Microsoft Graph application permissions could not be read.")
    else:
        perms = GraphPermissionsSection(
            **_read(snap, SRC_GRAPH_PERMISSIONS), items=index.graph_permissions.get(sp_id, []),
            note="Application permissions on Microsoft Graph only: other APIs are not read yet.",
        )
    if snap.delegated_permission_grants is None:
        consents = DelegatedPermissionsSection(status=NOT_READ, note="Delegated permission grants could not be read.")
    else:
        consents = DelegatedPermissionsSection(
            **_read(snap, SRC_DELEGATED_GRANTS), items=index.delegated_permissions.get(sp_id, []),
            note="Consents in this tenant. A delegated permission acts as the signed-in user, within that user's "
                 "own access, which this scan does not evaluate.",
        )
    if snap.directory_role_assignments is None:
        roles = DirectoryRolesSection(status=NOT_READ, note="Entra directory role assignments could not be read.")
    else:
        roles = DirectoryRolesSection(
            **_read(snap, SRC_DIRECTORY_ROLES), items=index.directory_roles.get(sp_id, []),
            note="Direct assignments only: roles held through groups and PIM eligibility are not read yet.",
        )
    if snap.azure_role_assignments is None:
        azure = AzureRolesSection(status=NOT_READ, note="Azure RBAC was not scanned or could not be read.")
    else:
        azure = AzureRolesSection(**_read(snap, SRC_AZURE_RBAC), items=index.azure_roles.get(sp_id, []))

    return IdentityRecord(
        profile=ProfileSection(
            **_read(snap, *directory),
            description=sp.get("description"),
            notes=sp.get("notes"),
            sign_in_audience=(app or {}).get("signInAudience"),
            publisher_domain=(app or {}).get("publisherDomain"),
            note=None if snap.owner_status_read else _PROFILE_PARTIAL,
        ),
        owners=OwnersSection(**_read(snap, *directory), items=owners,
                             note=_join(by_design, None if snap.owner_status_read else _OWNER_STATUS_NOT_READ)),
        sponsors=sponsors,
        credentials=CredentialsSection(**_read(snap, *directory), items=creds, note=cred_note),
        federated_credentials=federation,
        graph_permissions=perms,
        delegated_permissions=consents,
        directory_roles=roles,
        azure_roles=azure,
        activity=_activity(snap, sp.get("appId")),
    )

"""Synthetic tenant for ``--demo``: raw Graph/ARM-shaped data covering every rule.

Object IDs are derived with uuid5 so they — and therefore every finding_id —
are identical across demo runs, which lets Zetah show findings persisting
between scans. Timestamps are relative to "now".
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .snapshot import TenantSnapshot

DEMO_TENANT_ID = "demo-tenant-0000"
_NS = uuid.UUID("5a7e7a1e-0000-4000-8000-00000000d3e0")
_SUB = "00000000-0000-4000-8000-0000000000a1"


def _id(*parts: str) -> str:
    return str(uuid.uuid5(_NS, "/".join(parts)))


def _ts(d: datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


# Owners whose accounts are disabled: the people who left, still named as accountable.
_DISABLED_USERS = {"growth@demo-corp.example"}


def _user(upn: str) -> dict[str, Any]:
    return {"@odata.type": "#microsoft.graph.user", "id": _id("user", upn), "userPrincipalName": upn,
            "accountEnabled": upn not in _DISABLED_USERS}


def _publisher(name: Optional[str]) -> dict[str, Any]:
    return {"displayName": name or None}


def build_demo_snapshot(now: Optional[datetime] = None) -> TenantSnapshot:
    now = now or datetime.now(timezone.utc)
    ago = lambda days: _ts(now - timedelta(days=days))  # noqa: E731
    ahead = lambda days: _ts(now + timedelta(days=days))  # noqa: E731

    def secret(name: str, start_days_ago: int, end_in_days: int) -> dict[str, Any]:
        return {"keyId": _id("cred", name), "displayName": name, "hint": name[:3],
                "startDateTime": ago(start_days_ago), "endDateTime": ahead(end_in_days)}

    def cert(name: str, start_days_ago: int, end_in_days: int) -> dict[str, Any]:
        return {**secret(name, start_days_ago, end_in_days), "type": "AsymmetricX509Cert", "usage": "Verify"}

    apps: list[dict[str, Any]] = []
    sps: list[dict[str, Any]] = []

    def app(name: str, *, created_days_ago: int, owners: list[str], secrets: list[dict[str, Any]] = (),
            certs: list[dict[str, Any]] = (), audience: str = "AzureADMyOrg", tags: list[str] = (),
            sp_secrets: list[dict[str, Any]] = (), enabled: bool = True) -> str:
        app_id = _id("appId", name)
        owner_objs = [_user(u) for u in owners]
        apps.append({
            "id": _id("app", name), "appId": app_id, "displayName": name,
            "createdDateTime": ago(created_days_ago), "signInAudience": audience, "tags": list(tags),
            "publisherDomain": "demo-corp.onmicrosoft.com",
            "passwordCredentials": list(secrets), "keyCredentials": list(certs), "owners": owner_objs,
        })
        sps.append({
            "id": _id("sp", name), "appId": app_id, "displayName": name, "servicePrincipalType": "Application",
            "accountEnabled": enabled, "appOwnerOrganizationId": DEMO_TENANT_ID, "tags": list(tags),
            "verifiedPublisher": _publisher("Demo Corp"), "alternativeNames": [], "passwordCredentials": list(sp_secrets),
            "keyCredentials": [], "owners": [],
        })
        return _id("sp", name)

    def external_sp(name: str, owner_org: str, *, app_id: Optional[str] = None,
                    sp_secrets: list[dict[str, Any]] = (), publisher: str = "") -> str:
        sps.append({
            "id": _id("sp", name), "appId": app_id or _id("appId", name), "displayName": name,
            "servicePrincipalType": "Application", "accountEnabled": True, "appOwnerOrganizationId": owner_org,
            "tags": ["WindowsAzureActiveDirectoryIntegratedApp"], "verifiedPublisher": _publisher(publisher),
            "alternativeNames": [], "passwordCredentials": list(sp_secrets), "keyCredentials": [], "owners": [],
        })
        return _id("sp", name)

    def managed_identity(name: str, *, user_assigned: bool, resource: str) -> str:
        sps.append({
            "id": _id("sp", name), "appId": _id("appId", name), "displayName": name,
            "servicePrincipalType": "ManagedIdentity", "accountEnabled": True, "appOwnerOrganizationId": None,
            "tags": [], "verifiedPublisher": _publisher(None),
            "alternativeNames": [f"isExplicit={user_assigned}", resource],
            "passwordCredentials": [], "keyCredentials": [], "owners": [],
        })
        return _id("sp", name)

    def agent_identity(name: str, *, blueprint_app_id: str, sponsors: list[str]) -> str:
        """An Entra Agent ID agent identity: a service principal subtype, accountable humans are sponsors."""
        sps.append({
            "@odata.type": "#microsoft.graph.agentIdentity", "id": _id("sp", name), "appId": _id("appId", name),
            "displayName": name, "servicePrincipalType": "ServiceIdentity", "accountEnabled": True,
            "appOwnerOrganizationId": DEMO_TENANT_ID, "agentIdentityBlueprintId": blueprint_app_id, "tags": [],
            "verifiedPublisher": _publisher("Demo Corp"), "alternativeNames": [], "passwordCredentials": [],
            "keyCredentials": [], "owners": [], "sponsors": [_user(u) for u in sponsors],
        })
        return _id("sp", name)

    rg = f"/subscriptions/{_SUB}/resourceGroups"

    # --- the tenant -------------------------------------------------------- #
    ci = app("ci-deploy-pipeline", created_days_ago=900, owners=["devops-lead@demo-corp.example"],
             secrets=[secret("github-actions", 400, 330)])
    hr = app("legacy-hr-sync", created_days_ago=1600, owners=[],
             secrets=[secret("hr-2022", 1200, -412), secret("hr-2024", 600, -95), secret("hr-2025", 300, 430)])
    fin = app("Finance Copilot Agent", created_days_ago=210, owners=[], audience="AzureADMultipleOrgs",
              secrets=[secret("prod", 200, 530)])
    helpdesk = app("Helpdesk Assistant", created_days_ago=120, owners=["it-ops@demo-corp.example"], tags=["AIAgent"])
    idauto = app("Identity Automation", created_days_ago=700, owners=["iam-team@demo-corp.example"],
                 secrets=[secret("runner-a", 100, 265), secret("runner-b", 60, 305), secret("old-runner", 320, 45)])
    poc = app("marketing-analytics-poc", created_days_ago=300, owners=["growth@demo-corp.example"],
              secrets=[secret("poc", 168, 12)])
    payments = app("payments-api", created_days_ago=500, owners=["payments-team@demo-corp.example"],
                   certs=[cert("payments-2026", 90, 275)])
    spmig = app("sharepoint-migration-tool", created_days_ago=420, owners=["m365-admins@demo-corp.example"],
                sp_secrets=[secret("added-via-graph", 21, 709)])
    backup = external_sp("Acme Cloud Backup", "4c1e2a6b-0000-4000-8000-0000000acbe0", publisher="Acme Backup Inc.")
    exo = external_sp("Office 365 Exchange Online", "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
                      app_id="00000002-0000-0ff1-ce00-000000000000", publisher="Microsoft Services",
                      sp_secrets=[secret("sync", 9, 720)])
    # Microsoft first-party SP without extra credentials: must be ignored by the inventory
    msgraph = external_sp("Microsoft Graph", "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
                          app_id="00000003-0000-0000-c000-000000000000", publisher="Microsoft Services")
    arm = external_sp("Windows Azure Service Management API", "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
                      app_id="797f4846-ba00-4fd7-ba43-dac1f8f63013", publisher="Microsoft Services")
    sharepoint = external_sp("Office 365 SharePoint Online", "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
                             app_id="00000003-0000-0ff1-ce00-000000000000", publisher="Microsoft Services")
    # The same vendor's second app: a breach at Acme reaches both
    backup_sp = external_sp("Acme Backup for SharePoint", "4c1e2a6b-0000-4000-8000-0000000acbe0",
                            publisher="Acme Backup Inc.")
    # A third-party AI assistant that users connected to their mail and files themselves
    nimbus = external_sp("Nimbus AI Assistant", "6d2b9c41-0000-4000-8000-0000000a1a10", publisher="Nimbus Labs")
    mi_func = managed_identity("func-invoice-processor", user_assigned=False,
                               resource=f"{rg}/rg-finance/providers/Microsoft.Web/sites/func-invoice-processor")
    mi_aks = managed_identity("id-aks-workload", user_assigned=True,
                              resource=f"{rg}/rg-aks/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-aks-workload")
    mi_agent = managed_identity("id-foundry-research-agent", user_assigned=True,
                                resource=f"{rg}/rg-ai/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-foundry-research-agent")
    # Entra Agent ID: two agents created from the same blueprint, one with a sponsor, one without
    blueprint = _id("appId", "sales-workflows-blueprint")
    procurement = agent_identity("Procurement Agent", blueprint_app_id=blueprint,
                                 sponsors=["procurement-lead@demo-corp.example"])
    outreach = agent_identity("Sales Outreach Agent", blueprint_app_id=blueprint, sponsors=[])

    # --- Microsoft Graph application permissions --------------------------- #
    grants = {
        hr: ["Directory.ReadWrite.All", "User.Read.All"],
        fin: ["Mail.Read", "Files.Read.All", "Mail.Send"],
        helpdesk: ["Sites.Read.All", "User.Read.All"],
        idauto: ["RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All", "Application.Read.All"],
        spmig: ["Sites.FullControl.All"],
        backup: ["Mail.ReadWrite", "Files.Read.All"],
        mi_agent: ["Files.Read.All", "Mail.Send"],
        procurement: ["User.Read.All"],
        outreach: ["User.Read.All"],
        payments: ["User.Read.All"],
    }
    graph_roles = {_id("approle", p): p for plist in grants.values() for p in plist}
    graph_assignments = [
        {"id": _id("ara", sp, p), "principalId": sp, "principalType": "ServicePrincipal",
         "appRoleId": _id("approle", p), "resourceId": _id("sp", "Microsoft Graph")}
        for sp, plist in grants.items() for p in plist
    ]

    # --- application permissions on Exchange Online and SharePoint Online --- #
    resource_grants = {
        "00000002-0000-0ff1-ce00-000000000000": (exo, {backup: ["full_access_as_app"]}),
        "00000003-0000-0ff1-ce00-000000000000": (sharepoint, {backup_sp: ["Sites.FullControl.All", "User.Read.All"]}),
    }
    resource_roles = {api: {_id("approle", api, p): p for plist in g.values() for p in plist}
                      for api, (_, g) in resource_grants.items()}
    resource_assignments = {
        api: [{"id": _id("ara", sp, api, p), "principalId": sp, "principalType": "ServicePrincipal",
               "appRoleId": _id("approle", api, p), "resourceId": res}
              for sp, plist in g.items() for p in plist]
        for api, (res, g) in resource_grants.items()
    }

    # --- delegated permission grants (consents) ---------------------------- #
    def consent(client: str, resource: str, scope: str, user: Optional[str] = None) -> dict[str, Any]:
        principal = _id("user", user) if user else None
        return {"id": _id("grant", client, resource, user or "all"), "clientId": client, "resourceId": resource,
                "consentType": "Principal" if user else "AllPrincipals", "principalId": principal, "scope": scope}

    delegated = [
        # every user of the tenant: the in-house helpdesk agent reads SharePoint, and keeps that access offline
        consent(helpdesk, msgraph, "User.Read Sites.Read.All offline_access"),
        consent(payments, msgraph, "User.Read"),
        # three users connected the third-party assistant; one of them also let it manage Azure as them
        consent(nimbus, msgraph, "openid profile offline_access User.Read Mail.Read Mail.Send",
                "sales-lead@demo-corp.example"),
        consent(nimbus, msgraph, "openid profile offline_access User.Read Mail.Read Mail.Send Files.Read.All",
                "cfo@demo-corp.example"),
        consent(nimbus, msgraph, "openid profile offline_access User.Read Calendars.Read",
                "pm@demo-corp.example"),
        consent(nimbus, arm, "user_impersonation", "cfo@demo-corp.example"),
        # an administrator connected it too: for them the assistant acts as a Global Administrator
        consent(nimbus, msgraph, "openid offline_access User.Read Mail.Read Mail.Send", "it-admin@demo-corp.example"),
    ]

    # --- federated credentials (workload identity federation) ------------- #
    github = "https://token.actions.githubusercontent.com"

    def fic(name: str, subject: object, issuer: str = github) -> dict[str, Any]:
        return {"id": _id("fic", name), "name": name, "issuer": issuer, "subject": subject,
                "audiences": ["api://AzureADTokenExchange"]}

    app_fic: dict[str, list[dict[str, Any]]] = {a["id"]: [] for a in apps}
    # the pipeline deploys from any pull request, and holds Contributor and User Access Administrator
    app_fic[_id("app", "ci-deploy-pipeline")] = [fic("github-prs", "repo:demo-corp/infra:pull_request"),
                                                 fic("github-main", "repo:demo-corp/infra:ref:refs/heads/main")]
    app_fic[_id("app", "Identity Automation")] = [fic("github-prod", "repo:demo-corp/iam-automation:environment:production")]
    app_fic[_id("app", "payments-api")] = [fic("github-main", "repo:demo-corp/payments:ref:refs/heads/main")]
    # flexible credential: Graph v1.0 returns no subject for it
    app_fic[_id("app", "marketing-analytics-poc")] = [fic("github-any-branch", None)]
    mi_resource = {sp["id"]: next((n for n in sp["alternativeNames"] if n.startswith("/subscriptions/")), "")
                   for sp in sps if sp["servicePrincipalType"] == "ManagedIdentity"}
    mi_fic = {
        mi_aks: [dict(fic("aks-payments-api", "system:serviceaccount:payments:api",
                          "https://oidc.prod-aks.azure.com/00000000-0000-4000-8000-0000000000a1/"), identity_id=mi_resource[mi_aks])],
        mi_agent: [dict(fic("github-dev", "repo:demo-corp/research-agent:ref:refs/heads/dev"), identity_id=mi_resource[mi_agent])],
    }

    # --- Entra directory roles --------------------------------------------- #
    role_defs = {
        "62e90394-69f5-4237-9190-012177145e10": {"displayName": "Global Administrator",
                                                 "templateId": "62e90394-69f5-4237-9190-012177145e10"},
        "e8611ab8-c189-46e8-94e1-60213ab1f814": {"displayName": "Privileged Role Administrator",
                                                 "templateId": "e8611ab8-c189-46e8-94e1-60213ab1f814"},
        "fe930be7-5e62-47db-91af-98c3a49a38b1": {"displayName": "User Administrator",
                                                 "templateId": "fe930be7-5e62-47db-91af-98c3a49a38b1"},
        "88d8e3e3-8f55-4a1e-953a-9b9898b8876b": {"displayName": "Directory Readers",
                                                 "templateId": "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"},
    }
    dir_assignments = [
        {"id": _id("dra", idauto), "principalId": idauto, "directoryScopeId": "/",
         "roleDefinitionId": "e8611ab8-c189-46e8-94e1-60213ab1f814"},
        {"id": _id("dra", hr), "principalId": hr, "directoryScopeId": "/",
         "roleDefinitionId": "fe930be7-5e62-47db-91af-98c3a49a38b1"},
        {"id": _id("dra", payments), "principalId": payments, "directoryScopeId": "/",
         "roleDefinitionId": "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"},
    ]

    # --- Azure OpenAI and AI Services accounts ------------------------------ #
    def ai_account(name: str, kind: str, rg_name: str, *, local_auth: bool, public: bool) -> dict[str, Any]:
        rid = f"{rg}/{rg_name}/providers/Microsoft.CognitiveServices/accounts/{name}"
        return {"id": rid, "name": name, "kind": kind, "location": "westeurope", "sku": "S0",
                "endpoint": f"https://{name}.openai.azure.com/" if kind == "OpenAI" else f"https://{name}.cognitiveservices.azure.com/",
                "disable_local_auth": not local_auth, "public_network_access": "Enabled" if public else "Disabled",
                "network_default_action": "Allow" if public else "Deny"}

    ai_accounts = [
        ai_account("oai-finance-copilot", "OpenAI", "rg-finance", local_auth=True, public=True),
        ai_account("ais-research", "AIServices", "rg-ai", local_auth=True, public=False),
        ai_account("oai-helpdesk", "OpenAI", "rg-ai", local_auth=False, public=True),
    ]

    # --- Azure RBAC --------------------------------------------------------- #
    def ra(principal: str, role: str, scope: str) -> dict[str, Any]:
        return {"id": f"{scope}/providers/Microsoft.Authorization/roleAssignments/{_id('ra', principal, role, scope)}",
                "principalId": principal, "roleName": role, "scope": scope}

    azure = [
        ra(ci, "Contributor", f"/subscriptions/{_SUB}"),
        ra(ci, "User Access Administrator", f"{rg}/rg-platform"),
        ra(mi_func, "Owner", f"/subscriptions/{_SUB}"),
        ra(mi_aks, "Key Vault Secrets User", f"{rg}/rg-aks/providers/Microsoft.KeyVault/vaults/kv-aks"),
        ra(payments, "Contributor", f"{rg}/rg-payments"),
        # the finance agent can list the keys of its own OpenAI account
        ra(fin, "Cognitive Services User", ai_accounts[0]["id"]),
    ]

    # --- sign-in activity (appId -> last sign-in; absent = never) ---------- #
    by_sp = {sp["id"]: sp["appId"] for sp in sps}
    last_seen = {ci: 0, hr: 240, fin: 1, helpdesk: 3, idauto: 2, payments: 0, spmig: 4, backup: 0, backup_sp: 6, exo: 0,
                 nimbus: 0, mi_func: 0, mi_aks: 0, mi_agent: 1}
    signin = {by_sp[sp]: now - timedelta(days=d, hours=3) for sp, d in last_seen.items()}

    return TenantSnapshot(
        tenant_id=DEMO_TENANT_ID,
        tenant_name="Demo Corp (synthetic)",
        collected_at=now,
        applications=apps,
        service_principals=sps,
        graph_app_role_assignments=graph_assignments,
        graph_app_roles=graph_roles,
        resource_app_role_assignments=resource_assignments,
        resource_app_roles=resource_roles,
        directory_role_assignments=dir_assignments,
        directory_role_definitions=role_defs,
        signin_activity=signin,
        azure_role_assignments=azure,
        warnings=[],
        delegated_permission_grants=delegated,
        consenting_user_roles={_id("user", "it-admin@demo-corp.example"): [
            {"id": _id("dra", "it-admin"), "principalId": _id("user", "it-admin@demo-corp.example"),
             "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10", "directoryScopeId": "/"}]},
        consenting_users={_id("user", "it-admin@demo-corp.example"): {
            "userPrincipalName": "it-admin@demo-corp.example", "accountEnabled": True}},
        app_federated_credentials=app_fic,
        mi_federated_credentials=mi_fic,
        ai_accounts=ai_accounts,
    )


# --- scale tenant -------------------------------------------------------------------------------------------------- #
# The demo tenant above, padded with generated identities in the proportions of a large enterprise tenant: about a
# third of the inventory comes from app registrations (each one is two identities, the app and its service
# principal), a fifth from third-party apps of a few hundred vendors, a seventh from managed identities, a few percent
# from Entra Agent ID agents. Every rule has something to find, so the scan does the work it would do on a real tenant.

SCALE_SHARES = {"app_registration": 0.30, "external_app": 0.22, "managed_identity": 0.15, "agent": 0.03}
_MICROSOFT_TENANT = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
_GRAPH_PERMISSIONS = ["User.Read.All", "Mail.Read", "Mail.Send", "Files.Read.All", "Sites.Read.All", "Group.Read.All",
                      "Directory.Read.All", "Application.ReadWrite.All", "Sites.FullControl.All", "Mail.ReadWrite"]
_SCOPES = ["openid", "profile", "offline_access", "User.Read", "Mail.Read", "Mail.Send", "Files.Read.All",
           "Calendars.Read", "Sites.Read.All"]
_AZURE_ROLES = ["Reader", "Contributor", "Owner", "Key Vault Secrets User", "Storage Blob Data Reader",
                "User Access Administrator", "Cognitive Services User"]


def build_scale_snapshot(identities: int, seed: int = 7, now: Optional[datetime] = None) -> TenantSnapshot:
    """A tenant of about ``identities`` inventoried identities, the same on every run with the same seed."""

    if identities < 1:
        raise ValueError("identities must be at least 1")
    now = now or datetime.now(timezone.utc)
    snap = build_demo_snapshot(now)
    rnd = random.Random(seed)
    base = len(snap.applications) * 2 + sum(
        1 for sp in snap.service_principals if sp.get("appOwnerOrganizationId") != _MICROSOFT_TENANT
    )
    extra = max(0, identities - base)
    n_apps = round(extra * SCALE_SHARES["app_registration"])
    n_ext = round(extra * SCALE_SHARES["external_app"])
    n_agents = round(extra * SCALE_SHARES["agent"])
    n_mi = max(0, extra - 2 * n_apps - n_ext - n_agents)

    ts = lambda days: _ts(now + timedelta(days=days))  # noqa: E731
    users = [f"user{i:05d}@demo-corp.example" for i in range(max(50, extra // 20))]
    disabled = set(rnd.sample(users, len(users) // 20))
    user_obj = lambda upn: {"@odata.type": "#microsoft.graph.user", "id": _id("user", upn),  # noqa: E731
                            "userPrincipalName": upn, "accountEnabled": upn not in disabled}
    vendors = [(_id("vendor", str(i)), f"Vendor {i:03d} Ltd") for i in range(max(20, n_ext // 60))]
    msgraph = next(sp["id"] for sp in snap.service_principals if sp["appId"] == "00000003-0000-0000-c000-000000000000")
    exo = next(sp["id"] for sp in snap.service_principals if sp["appId"] == "00000002-0000-0ff1-ce00-000000000000")
    spo = next(sp["id"] for sp in snap.service_principals if sp["appId"] == "00000003-0000-0ff1-ce00-000000000000")

    def creds(kind: str, name: str, count: int) -> list[dict[str, Any]]:
        out = []
        for i in range(count):
            start = -rnd.randint(1, 1500)
            c = {"keyId": _id("cred", name, str(i)), "displayName": f"{kind}-{i}", "hint": "abc",
                 "startDateTime": ts(start), "endDateTime": ts(start + rnd.choice([90, 180, 365, 730, 3650]))}
            if kind == "cert":
                c.update(type="AsymmetricX509Cert", usage="Verify")
            out.append(c)
        return out

    sp_ids: list[str] = []
    ext_ids: list[str] = []
    mi_ids: list[str] = []
    for i in range(n_apps):
        name = f"app-{i:06d}"
        app_id = _id("appId", name)
        owners = [user_obj(u) for u in rnd.sample(users, rnd.choice([0, 0, 1, 1, 1, 2]))]
        snap.applications.append({
            "id": _id("app", name), "appId": app_id, "displayName": name,
            "createdDateTime": ts(-rnd.randint(1, 2500)),
            "signInAudience": "AzureADMultipleOrgs" if rnd.random() < 0.1 else "AzureADMyOrg",
            "tags": ["AIAgent"] if rnd.random() < 0.01 else [], "publisherDomain": "demo-corp.onmicrosoft.com",
            "passwordCredentials": creds("secret", name, rnd.choice([0, 0, 1, 1, 2, 3])),
            "keyCredentials": creds("cert", name + "/c", 1 if rnd.random() < 0.15 else 0), "owners": owners,
        })
        sid = _id("sp", name)
        snap.service_principals.append({
            "id": sid, "appId": app_id, "displayName": name, "servicePrincipalType": "Application",
            "accountEnabled": rnd.random() > 0.03, "appOwnerOrganizationId": DEMO_TENANT_ID, "tags": [],
            "verifiedPublisher": _publisher("Demo Corp"), "alternativeNames": [],
            "passwordCredentials": creds("secret", name + "/sp", 1) if rnd.random() < 0.01 else [],
            "keyCredentials": [], "owners": [],
        })
        sp_ids.append(sid)
    for i in range(n_ext):
        org, publisher = rnd.choice(vendors)
        name = f"{publisher} app {i:06d}"
        sid = _id("sp", "ext", str(i))
        snap.service_principals.append({
            "id": sid, "appId": _id("appId", "ext", str(i)), "displayName": name,
            "servicePrincipalType": "Application", "accountEnabled": True, "appOwnerOrganizationId": org,
            "tags": ["WindowsAzureActiveDirectoryIntegratedApp"],
            "verifiedPublisher": _publisher(publisher if rnd.random() < 0.6 else None), "alternativeNames": [],
            "passwordCredentials": [], "keyCredentials": [], "owners": [],
        })
        ext_ids.append(sid)
    for i in range(n_mi):
        user_assigned = rnd.random() < 0.35
        name = f"id-workload-{i:06d}" if user_assigned else f"func-{i:06d}"
        provider = "Microsoft.ManagedIdentity/userAssignedIdentities" if user_assigned else "Microsoft.Web/sites"
        sid = _id("sp", "mi", str(i))
        snap.service_principals.append({
            "id": sid, "appId": _id("appId", "mi", str(i)), "displayName": name,
            "servicePrincipalType": "ManagedIdentity", "accountEnabled": True, "appOwnerOrganizationId": None,
            "tags": [], "verifiedPublisher": _publisher(None),
            "alternativeNames": [f"isExplicit={user_assigned}",
                                 f"/subscriptions/{_SUB}/resourceGroups/rg-{i % 400:03d}/providers/{provider}/{name}"],
            "passwordCredentials": [], "keyCredentials": [], "owners": [],
        })
        mi_ids.append(sid)
    blueprint = _id("appId", "sales-workflows-blueprint")
    agent_ids = []
    for i in range(n_agents):
        name = f"agent-{i:05d}"
        sid = _id("sp", "agent", str(i))
        snap.service_principals.append({
            "@odata.type": "#microsoft.graph.agentIdentity", "id": sid, "appId": _id("appId", "agent", str(i)),
            "displayName": name, "servicePrincipalType": "ServiceIdentity", "accountEnabled": True,
            "appOwnerOrganizationId": DEMO_TENANT_ID, "agentIdentityBlueprintId": blueprint, "tags": [],
            "verifiedPublisher": _publisher("Demo Corp"), "alternativeNames": [], "passwordCredentials": [],
            "keyCredentials": [], "owners": [],
            "sponsors": [user_obj(u) for u in rnd.sample(users, rnd.choice([0, 1, 1, 1]))],
        })
        agent_ids.append(sid)

    # application permissions: a tenth of the service principals hold some, a few on Exchange and SharePoint
    for sid in rnd.sample(sp_ids + ext_ids + mi_ids + agent_ids, (len(sp_ids) + len(ext_ids) + len(mi_ids)) // 10):
        for perm in rnd.sample(_GRAPH_PERMISSIONS, rnd.randint(1, 3)):
            role = _id("approle", perm)
            snap.graph_app_roles[role] = perm
            snap.graph_app_role_assignments.append({"id": _id("ara", sid, perm), "principalId": sid,
                                                    "principalType": "ServicePrincipal", "appRoleId": role,
                                                    "resourceId": msgraph})
    resource = {"00000002-0000-0ff1-ce00-000000000000": (exo, "full_access_as_app"),
                "00000003-0000-0ff1-ce00-000000000000": (spo, "Sites.FullControl.All")}
    for sid in rnd.sample(ext_ids, len(ext_ids) // 100):
        api = rnd.choice(list(resource))
        res, perm = resource[api]
        role = _id("approle", api, perm)
        snap.resource_app_roles.setdefault(api, {})[role] = perm
        snap.resource_app_role_assignments[api].append({"id": _id("ara", sid, api, perm), "principalId": sid,
                                                        "principalType": "ServicePrincipal", "appRoleId": role,
                                                        "resourceId": res})
    # consents: a fifth of the third-party apps, for every user or for a few users each
    for sid in rnd.sample(ext_ids, len(ext_ids) // 5):
        scope = " ".join(rnd.sample(_SCOPES, rnd.randint(2, 6)))
        if rnd.random() < 0.3:
            snap.delegated_permission_grants.append({"id": _id("grant", sid, "all"), "clientId": sid,
                                                     "resourceId": msgraph, "consentType": "AllPrincipals",
                                                     "principalId": None, "scope": scope})
        else:
            for u in rnd.sample(users, rnd.randint(1, 4)):
                snap.delegated_permission_grants.append({"id": _id("grant", sid, u), "clientId": sid,
                                                         "resourceId": msgraph, "consentType": "Principal",
                                                         "principalId": _id("user", u), "scope": scope})
    # federated credentials on a tenth of the app registrations, some trusting every pull request
    for app in rnd.sample(snap.applications[len(snap.applications) - n_apps:], n_apps // 10):
        subject = rnd.choice(["ref:refs/heads/main", "environment:production", "pull_request"])
        snap.app_federated_credentials[app["id"]] = [{
            "id": _id("fic", app["id"]), "name": "github", "issuer": "https://token.actions.githubusercontent.com",
            "subject": f"repo:demo-corp/{app['displayName']}:{subject}", "audiences": ["api://AzureADTokenExchange"]}]
    for app in snap.applications:
        snap.app_federated_credentials.setdefault(app["id"], [])
    # Azure RBAC: half of the managed identities and a tenth of the app service principals
    for sid in rnd.sample(mi_ids, len(mi_ids) // 2) + rnd.sample(sp_ids, len(sp_ids) // 10):
        role = rnd.choice(_AZURE_ROLES)
        scope = f"/subscriptions/{_SUB}"
        if rnd.random() >= 0.1:
            scope += f"/resourceGroups/rg-{rnd.randint(0, 399):03d}"
        snap.azure_role_assignments.append({
            "id": f"{scope}/providers/Microsoft.Authorization/roleAssignments/{_id('ra', sid, role, scope)}",
            "principalId": sid, "roleName": role, "scope": scope})
    # Entra roles on a few service principals
    roles = list(snap.directory_role_definitions)
    for sid in rnd.sample(sp_ids, len(sp_ids) // 200):
        snap.directory_role_assignments.append({"id": _id("dra", sid), "principalId": sid, "directoryScopeId": "/",
                                                "roleDefinitionId": rnd.choice(roles)})
    # sign-ins: most identities were seen recently, some long ago, some never
    by_id = {sp["id"]: sp["appId"] for sp in snap.service_principals}
    for sid in sp_ids + ext_ids + mi_ids + agent_ids:
        r = rnd.random()
        if r < 0.85:
            days = rnd.randint(0, 30) if r < 0.7 else rnd.randint(91, 900)
            snap.signin_activity[by_id[sid]] = now - timedelta(days=days)
    snap.tenant_name = f"Demo Corp at scale ({identities:,} identities, synthetic)"
    return snap

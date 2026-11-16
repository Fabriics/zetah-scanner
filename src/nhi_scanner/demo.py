"""Synthetic tenant for ``--demo``: raw Graph/ARM-shaped data covering every rule.

Object IDs are derived with uuid5 so they — and therefore every finding_id —
are identical across demo runs, which lets Zetah show findings persisting
between scans. Timestamps are relative to "now".
"""

from __future__ import annotations

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
    last_seen = {ci: 0, hr: 240, fin: 1, helpdesk: 3, idauto: 2, payments: 0, spmig: 4, backup: 0, exo: 0,
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

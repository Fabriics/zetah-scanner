"""Detection rules.

Each rule emits at most ONE finding per entity, aggregating every instance it
found (all expired secrets, all privileged role assignments, ...) into
``evidence``. That is what makes ``finding_id = sha256(tenant+entity+rule)``
stable across scans: the issue keeps its identity while it stays open.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Optional

from .inventory import Inventory
from .models import EntityType, FindingCategory, NHIEntity, SecurityFinding, Severity
from .snapshot import TenantSnapshot, parse_graph_datetime

GRAPH_API = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"

# --------------------------------------------------------------------------- #
# Knowledge base
# --------------------------------------------------------------------------- #

# Graph application permissions that lead to full tenant takeover.
TIER0_GRAPH_PERMISSIONS: dict[str, str] = {
    "RoleManagement.ReadWrite.Directory": "can assign itself (or anyone) Global Administrator",
    "AppRoleAssignment.ReadWrite.All": "can grant itself any Graph permission, including RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All": "can add credentials to any other app or service principal and act as it",
    "Directory.ReadWrite.All": "can modify users, groups and service principals across the directory",
    "UserAuthenticationMethod.ReadWrite.All": "can register a Temporary Access Pass on any user, including Global Administrators",
    "Domain.ReadWrite.All": "can federate a domain with an attacker-controlled IdP and forge sign-ins for any user",
    "Policy.ReadWrite.ConditionalAccess": "can disable Conditional Access and MFA requirements tenant-wide",
    "Policy.ReadWrite.PermissionGrant": "can rewrite consent policies to self-approve any permission",
    "PrivilegedAccess.ReadWrite.AzureADGroup": "can add itself to privileged (role-assignable) groups via PIM",
    "RoleAssignmentSchedule.ReadWrite.Directory": "can activate privileged directory roles through PIM",
    "RoleEligibilitySchedule.ReadWrite.Directory": "can make any principal eligible for privileged directory roles",
}

# Graph application permissions with tenant-wide data access or impersonation power.
HIGH_IMPACT_GRAPH_PERMISSIONS: dict[str, str] = {
    "Mail.ReadWrite": "read and modify every mailbox",
    "Mail.Read": "read every mailbox in the tenant",
    "Mail.Send": "send mail as any user (BEC / internal phishing)",
    "Files.ReadWrite.All": "read and overwrite every OneDrive/SharePoint file",
    "Files.Read.All": "read every OneDrive/SharePoint file",
    "Sites.FullControl.All": "full control of every SharePoint site",
    "Sites.ReadWrite.All": "read and write every SharePoint site",
    "Sites.Read.All": "read every SharePoint site",
    "Chat.Read.All": "read every Teams chat",
    "Chat.ReadWrite.All": "read and post in every Teams chat",
    "ChannelMessage.Read.All": "read every Teams channel message",
    "User.ReadWrite.All": "modify any user profile and properties",
    "Group.ReadWrite.All": "change membership of any non-role-assignable group",
    "Calendars.ReadWrite": "read and modify every calendar",
    "Contacts.ReadWrite": "read and modify every contact list",
    "Notes.ReadWrite.All": "read and modify every OneNote notebook",
}

# Agent "excessive agency": permissions that let an agent act, not just read.
AGENT_ACTION_PERMISSIONS = {
    "Mail.Send", "Mail.ReadWrite", "Files.ReadWrite.All", "Sites.ReadWrite.All", "Sites.FullControl.All",
    "Chat.ReadWrite.All", "ChannelMessage.Send", "User.ReadWrite.All", "Group.ReadWrite.All",
    "Calendars.ReadWrite", "Contacts.ReadWrite", "Notes.ReadWrite.All",
} | set(TIER0_GRAPH_PERMISSIONS)
AGENT_BROAD_READ_PERMISSIONS = {
    "Mail.Read", "Mail.ReadWrite", "Files.Read.All", "Files.ReadWrite.All", "Sites.Read.All",
    "Sites.ReadWrite.All", "Sites.FullControl.All", "Chat.Read.All", "Chat.ReadWrite.All", "ChannelMessage.Read.All",
}
AGENT_EGRESS_PERMISSIONS = {"Mail.Send", "Chat.ReadWrite.All", "ChannelMessage.Send"} | set(TIER0_GRAPH_PERMISSIONS)

# Built-in directory roles by templateId -> (name, severity).
PRIVILEGED_DIRECTORY_ROLES: dict[str, tuple[str, Severity]] = {
    "62e90394-69f5-4237-9190-012177145e10": ("Global Administrator", Severity.CRITICAL),
    "e8611ab8-c189-46e8-94e1-60213ab1f814": ("Privileged Role Administrator", Severity.CRITICAL),
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": ("Privileged Authentication Administrator", Severity.CRITICAL),
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": ("Application Administrator", Severity.CRITICAL),
    "158c047a-c907-4556-b7ef-446551a6b5f7": ("Cloud Application Administrator", Severity.CRITICAL),
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": ("Hybrid Identity Administrator", Severity.CRITICAL),
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": ("Conditional Access Administrator", Severity.CRITICAL),
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": ("Authentication Administrator", Severity.HIGH),
    "194ae4cb-b126-40b2-bd5b-6091b380977d": ("Security Administrator", Severity.HIGH),
    "29232cdf-9323-42fd-ade2-1d097af3e4de": ("Exchange Administrator", Severity.HIGH),
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": ("SharePoint Administrator", Severity.HIGH),
    "fe930be7-5e62-47db-91af-98c3a49a38b1": ("User Administrator", Severity.HIGH),
    "3a2c62db-5318-420d-8d74-23affee5d9d5": ("Intune Administrator", Severity.HIGH),
    "fdd7a751-b60b-444a-984c-02652fe8fa1c": ("Groups Administrator", Severity.HIGH),
}

# Exchange, SharePoint and Skype hybrid setups legitimately upload a certificate to these Microsoft apps.
HYBRID_FIRST_PARTY_APPS = {
    "00000002-0000-0ff1-ce00-000000000000": "Exchange Online",
    "00000003-0000-0ff1-ce00-000000000000": "SharePoint Online",
    "00000004-0000-0ff1-ce00-000000000000": "Skype for Business Online",
}

AZURE_ACCESS_CONTROL_ROLES = {"Owner", "User Access Administrator", "Role Based Access Control Administrator"}
MULTI_TENANT_AUDIENCES = {"AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount"}


@dataclass
class RuleConfig:
    dormant_days: int = 90
    max_secret_lifetime_days: int = 365
    expiring_soon_days: int = 30


# --------------------------------------------------------------------------- #
# Context
# --------------------------------------------------------------------------- #


@dataclass
class RuleContext:
    tenant_id: str
    now: datetime
    snap: TenantSnapshot
    inv: Inventory
    cfg: RuleConfig
    graph_perms: dict[str, list[dict[str, str]]] = field(default_factory=dict)  # spId -> [{permission, assignment_id}]
    dir_roles: dict[str, list[dict[str, Any]]] = field(default_factory=dict)  # spId -> [{role, severity, ...}]
    azure_roles: dict[str, list[dict[str, Any]]] = field(default_factory=dict)  # spId -> [{role, scope, level, id}]
    privileged_sp_ids: set[str] = field(default_factory=set)

    def finding(self, entity: NHIEntity, rule_id: str, **fields: Any) -> SecurityFinding:
        return SecurityFinding.create(tenant_id=self.tenant_id, entity=entity, rule_id=rule_id, **fields)

    def perms(self, entity: NHIEntity) -> set[str]:
        return {p["permission"] for p in self.graph_perms.get(entity.entity_id, [])}


def _scope_level(scope: str) -> str:
    s = scope.lower().rstrip("/")
    if s == "":
        return "root"
    if "/providers/microsoft.management/managementgroups/" in s:
        return "management_group"
    parts = s.split("/")
    if len(parts) == 3:
        return "subscription"
    if len(parts) == 5 and parts[3] == "resourcegroups":
        return "resource_group"
    return "resource"


def build_context(snap: TenantSnapshot, inv: Inventory, cfg: RuleConfig, now: datetime) -> RuleContext:
    ctx = RuleContext(tenant_id=snap.tenant_id, now=now, snap=snap, inv=inv, cfg=cfg)

    perms: dict[str, list[dict[str, str]]] = defaultdict(list)
    for a in snap.graph_app_role_assignments or []:
        name = snap.graph_app_roles.get(a["appRoleId"])
        if name:
            perms[a["principalId"]].append({"permission": name, "assignment_id": a["id"]})
    ctx.graph_perms = dict(perms)

    roles: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for a in snap.directory_role_assignments or []:
        rdef = snap.directory_role_definitions.get(a["roleDefinitionId"], {})
        template = rdef.get("templateId") or a["roleDefinitionId"]
        if template in PRIVILEGED_DIRECTORY_ROLES:
            name, sev = PRIVILEGED_DIRECTORY_ROLES[template]
            scope = a.get("directoryScopeId") or "/"
            # limited to an administrative unit or a single application: not a tenant-wide role
            scoped = scope != "/"
            roles[a["principalId"]].append({
                "role": f"{name} (scoped)" if scoped else name,
                "severity": Severity.MEDIUM if scoped else sev,
                "assignment_id": a["id"],
                "directory_scope": scope,
            })
    ctx.dir_roles = dict(roles)

    az: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ra in snap.azure_role_assignments or []:
        az[ra["principalId"]].append({**ra, "level": _scope_level(ra["scope"])})
    ctx.azure_roles = dict(az)

    for sp_id, plist in ctx.graph_perms.items():
        if any(p["permission"] in TIER0_GRAPH_PERMISSIONS for p in plist):
            ctx.privileged_sp_ids.add(sp_id)
    for sp_id, rlist in ctx.dir_roles.items():
        if any(r["severity"] is Severity.CRITICAL for r in rlist):
            ctx.privileged_sp_ids.add(sp_id)
    for sp_id, alist in ctx.azure_roles.items():
        if any(a["roleName"] in AZURE_ACCESS_CONTROL_ROLES and a["level"] != "resource" for a in alist):
            ctx.privileged_sp_ids.add(sp_id)
    return ctx


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

RuleFn = Callable[[RuleContext], list[SecurityFinding]]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: FindingCategory
    requires: Optional[str]  # "signin" | "azure" | "graph_permissions" | "directory_roles" | None
    title: str  # what the rule checks, for reports
    action: str  # the remediation in one line, for reports
    fn: RuleFn


RULES: list[Rule] = []


def rule(
    rule_id: str, category: FindingCategory, requires: Optional[str] = None, *, title: str, action: str,
) -> Callable[[RuleFn], RuleFn]:
    def deco(fn: RuleFn) -> RuleFn:
        RULES.append(Rule(rule_id, category, requires, title, action, fn))
        return fn
    return deco


def run_rules(ctx: RuleContext) -> tuple[list[SecurityFinding], list[str]]:
    available = {
        "signin": ctx.snap.signin_activity is not None,
        "azure": ctx.snap.azure_role_assignments is not None,
        "graph_permissions": ctx.snap.graph_app_role_assignments is not None,
        "directory_roles": ctx.snap.directory_role_assignments is not None,
    }
    findings: list[SecurityFinding] = []
    evaluated: list[str] = []
    for r in RULES:
        if r.requires and not available[r.requires]:
            continue
        evaluated.append(r.rule_id)
        for f in r.fn(ctx):
            assert f.rule_id == r.rule_id and f.category is r.category, f"rule {r.rule_id} emitted inconsistent finding"
            findings.append(f)
    findings.sort(key=lambda f: (-f.severity.rank, f.rule_id, f.entity_name))
    return findings, evaluated


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _credentials(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """Secrets and certificates of an application or service principal, normalised."""
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


def _active(creds: list[dict[str, Any]], now: datetime) -> list[dict[str, Any]]:
    return [c for c in creds if c["end"] is None or c["end"] > now]


def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else None


def _app_entities(ctx: RuleContext) -> list[tuple[NHIEntity, dict[str, Any]]]:
    return [
        (e, ctx.inv.app_by_app_id[e.app_id])
        for e in ctx.inv.entities
        if e.entity_type is EntityType.APP_REGISTRATION
    ]


def _sp_entities(ctx: RuleContext) -> list[NHIEntity]:
    return [e for e in ctx.inv.entities if e.entity_type is not EntityType.APP_REGISTRATION]


def _is_managed_identity(entity: NHIEntity) -> bool:
    return entity.raw_metadata.get("servicePrincipalType") == "ManagedIdentity"


def _app_cred_delete(app_id: Optional[str], cred: dict[str, Any]) -> str:
    return (f"az ad app credential delete --id {app_id} --key-id {cred['key_id']}"
            + (" --cert" if cred["kind"] == "certificate" else ""))


def _sp_cred_delete(sp_id: str, cred: dict[str, Any]) -> str:
    return (f"az ad sp credential delete --id {sp_id} --key-id {cred['key_id']}"
            + (" --cert" if cred["kind"] == "certificate" else ""))


def _hold(command: str) -> str:
    """Comment a command out: pasting a whole block must never remove a credential still in use."""
    return f"# {command}"


_FEDERATED_EXAMPLE = json.dumps({
    "name": "github-main",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:<ORG>/<REPO>:ref:refs/heads/main",
    "audiences": ["api://AzureADTokenExchange"],
}, separators=(",", ":"))


def _federation_steps(app_id: Optional[str], then_delete: list[str]) -> list[str]:
    steps = [
        "# 1. Add a federated credential for the workload. Adapt issuer and subject (GitHub Actions example):",
        _hold(f"az ad app federated-credential create --id {app_id} --parameters '{_FEDERATED_EXAMPLE}'"),
        "# 2. Switch the workload to it and confirm it signs in.",
    ]
    if then_delete:
        steps += ["# 3. Only then delete the old secret(s):", *map(_hold, then_delete)]
    return steps


def _blast_radius(ctx: RuleContext, sp_id: Optional[str]) -> str:
    if not sp_id:
        return "It has no service principal in this tenant, so its direct blast radius here is limited."
    parts = []
    tier0 = sorted(ctx.perms(ctx.inv.by_id[sp_id]) & set(TIER0_GRAPH_PERMISSIONS)) if sp_id in ctx.inv.by_id else []
    if tier0:
        parts.append(f"Graph {', '.join(tier0)}")
    roles = [r["role"] for r in ctx.dir_roles.get(sp_id, [])]
    if roles:
        parts.append(f"directory role(s) {', '.join(sorted(set(roles)))}")
    az = [f"{a['roleName']} on {a['level'].replace('_', ' ')}" for a in ctx.azure_roles.get(sp_id, [])
          if a["roleName"] in AZURE_ACCESS_CONTROL_ROLES | {"Contributor"}]
    if az:
        parts.append(f"Azure {', '.join(sorted(set(az)))}")
    if not parts:
        return "Whoever holds it inherits every permission granted to the identity."
    return f"Whoever holds it inherits {'; '.join(parts)} — a direct privilege-escalation path."


# --------------------------------------------------------------------------- #
# secret_hygiene
# --------------------------------------------------------------------------- #


@rule(
    "NHI-SEC-001", FindingCategory.SECRET_HYGIENE,
    title="Expired credentials still attached",
    action="Delete expired secrets and certificates",
)
def expired_credentials(ctx: RuleContext) -> list[SecurityFinding]:
    out = []
    for entity, app in _app_entities(ctx):
        expired = [c for c in _credentials(app) if c["end"] and c["end"] <= ctx.now]
        if not expired:
            continue
        evidence = [
            {"kind": c["kind"], "key_id": c["key_id"], "display_name": c["display_name"],
             "expired_on": _iso(c["end"]), "days_expired": (ctx.now - c["end"]).days}
            for c in expired
        ]
        cmds = [_app_cred_delete(entity.app_id, c) for c in expired]
        out.append(ctx.finding(
            entity, "NHI-SEC-001",
            category=FindingCategory.SECRET_HYGIENE,
            severity=Severity.LOW,
            title=f"{len(expired)} expired credential(s) still attached",
            description=(
                f"App registration '{entity.display_name}' still carries {len(expired)} expired "
                f"secret/certificate(s), the oldest expired {max(e['days_expired'] for e in evidence)} days ago. "
                "They no longer authenticate but signal an unmanaged rotation process."
            ),
            attack_path_context=(
                "Expired credentials cannot mint tokens, but stale credential slots hide which secrets are "
                "actually in use, making a newly planted attacker secret harder to spot during review."
            ),
            remediation_cli="\n".join(cmds),
            evidence={"credentials": evidence, "max_days_expired": max(e["days_expired"] for e in evidence)},
        ))
    return out


@rule(
    "NHI-SEC-002", FindingCategory.SECRET_HYGIENE,
    title="Long-lived client secrets",
    action="Replace with workload identity federation, or rotate to secrets of 180 days or less",
)
def long_lived_secrets(ctx: RuleContext) -> list[SecurityFinding]:
    out = []
    limit = ctx.cfg.max_secret_lifetime_days
    for entity, app in _app_entities(ctx):
        long_lived = []
        for c in _active(_credentials(app), ctx.now):
            if c["kind"] != "client_secret" or not c["start"] or not c["end"]:
                continue
            lifetime = (c["end"] - c["start"]).days
            if lifetime > limit:
                long_lived.append({**c, "lifetime_days": lifetime})
        if not long_lived:
            continue
        worst = max(c["lifetime_days"] for c in long_lived)
        sp_id = entity.raw_metadata.get("service_principal_id")
        out.append(ctx.finding(
            entity, "NHI-SEC-002",
            category=FindingCategory.SECRET_HYGIENE,
            # +1 tolerates the leap day in the portal's "24 months" option
            severity=Severity.HIGH if worst > 2 * limit + 1 or sp_id in ctx.privileged_sp_ids else Severity.MEDIUM,
            title=f"Client secret valid for {worst} days",
            description=(
                f"'{entity.display_name}' has {len(long_lived)} active client secret(s) with a lifetime above "
                f"{limit} days (longest: {worst} days). Long-lived static secrets end up in config files, "
                "CI variables and chat history."
            ),
            attack_path_context=(
                "A leaked long-lived secret stays valid for months without anyone noticing. "
                + _blast_radius(ctx, sp_id)
            ),
            remediation_cli="\n".join(
                _federation_steps(entity.app_id, [_app_cred_delete(entity.app_id, c) for c in long_lived])
            ),
            evidence={
                "max_lifetime_days": worst,
                "policy_max_days": limit,
                "credentials": [
                    {"key_id": c["key_id"], "display_name": c["display_name"], "lifetime_days": c["lifetime_days"],
                     "expires_on": _iso(c["end"])}
                    for c in long_lived
                ],
            },
        ))
    return out


@rule(
    "NHI-SEC-003", FindingCategory.SECRET_HYGIENE,
    title="Multiple active client secrets",
    action="Keep the one secret in use and delete the others",
)
def multiple_active_secrets(ctx: RuleContext) -> list[SecurityFinding]:
    out = []
    for entity, app in _app_entities(ctx):
        secrets = [c for c in _active(_credentials(app), ctx.now) if c["kind"] == "client_secret"]
        if len(secrets) < 2:
            continue
        out.append(ctx.finding(
            entity, "NHI-SEC-003",
            category=FindingCategory.SECRET_HYGIENE,
            severity=Severity.MEDIUM,
            title=f"{len(secrets)} active client secrets",
            description=(
                f"'{entity.display_name}' has {len(secrets)} simultaneously valid client secrets. Only one should "
                "exist outside a short rotation window; extra secrets are usually forgotten copies."
            ),
            attack_path_context=(
                "Every additional valid secret is another place the identity can leak from, and an attacker-added "
                "secret blends in among legitimate ones. " + _blast_radius(ctx, entity.raw_metadata.get("service_principal_id"))
            ),
            remediation_cli="\n".join([
                f"az ad app credential list --id {entity.app_id} -o table",
                "# Find the secret in use (workload configuration, sign-in logs), then delete only the others:",
                *[_hold(_app_cred_delete(entity.app_id, c)) for c in secrets],
            ]),
            evidence={"active_secret_count": len(secrets), "key_ids": [c["key_id"] for c in secrets]},
        ))
    return out


@rule(
    "NHI-SEC-004", FindingCategory.SECRET_HYGIENE,
    title="Credentials on the service principal object",
    action="Remove the credentials and investigate who added them",
)
def credentials_on_service_principal(ctx: RuleContext) -> list[SecurityFinding]:
    out = []
    for entity in _sp_entities(ctx):
        sp = ctx.inv.sp_by_id[entity.entity_id]
        # SAML enterprise apps legitimately keep their token-signing certificate on the SP,
        # and managed identities always hold a platform-managed one
        if sp.get("preferredSingleSignOnMode") == "saml" or _is_managed_identity(entity):
            continue
        creds = _active(_credentials(sp), ctx.now)
        if not creds:
            continue
        first_party = entity.raw_metadata.get("is_microsoft_first_party")
        evidence = {
            "microsoft_first_party": bool(first_party),
            "credentials": [
                {"kind": c["kind"], "key_id": c["key_id"], "display_name": c["display_name"],
                 "created": _iso(c["start"]), "expires_on": _iso(c["end"])}
                for c in creds
            ],
        }
        deletes = [_hold(_sp_cred_delete(entity.entity_id, c)) for c in creds]
        hybrid_app = HYBRID_FIRST_PARTY_APPS.get(entity.app_id or "") if first_party else None
        if hybrid_app and all(c["kind"] == "certificate" for c in creds):
            out.append(ctx.finding(
                entity, "NHI-SEC-004",
                category=FindingCategory.SECRET_HYGIENE,
                severity=Severity.MEDIUM,
                title=f"Certificate on {hybrid_app}: confirm it belongs to the hybrid setup",
                description=(
                    f"Service principal '{entity.display_name}' has {len(creds)} certificate(s). Hybrid "
                    f"{hybrid_app} deployments upload one here, so this is usually expected, but the same "
                    "technique has been used for persistence."
                ),
                attack_path_context=(
                    "A certificate that the hybrid administrators do not recognise would let its holder act as "
                    "this Microsoft service. " + _blast_radius(ctx, entity.entity_id)
                ),
                remediation_cli="\n".join([
                    f"az ad sp credential list --id {entity.entity_id} --cert -o table",
                    "# Hybrid features depend on this certificate. Delete it only if its administrators do not "
                    "recognise it:",
                    *deletes,
                ]),
                evidence=evidence,
            ))
            continue
        out.append(ctx.finding(
            entity, "NHI-SEC-004",
            category=FindingCategory.SECRET_HYGIENE,
            severity=Severity.CRITICAL if first_party or entity.entity_id in ctx.privileged_sp_ids else Severity.HIGH,
            title=("Credentials added to a Microsoft first-party service principal" if first_party
                   else "Credentials set directly on the service principal"),
            description=(
                f"Service principal '{entity.display_name}' has {len(creds)} credential(s) set on the service "
                "principal object itself. These do not appear under 'Certificates & secrets' in the portal and are "
                "a well-known persistence technique (Solorigate / Midnight Blizzard)."
            ),
            attack_path_context=(
                "An attacker with Application.ReadWrite.All or Application Administrator can silently add a secret "
                "here and authenticate as this identity indefinitely. " + _blast_radius(ctx, entity.entity_id)
            ),
            remediation_cli="\n".join([
                "# Check who added them (Entra audit log: 'Add service principal credentials'), then delete "
                "what nobody recognises:",
                *deletes,
            ]),
            evidence=evidence,
        ))
    return out


@rule(
    "NHI-SEC-005", FindingCategory.SECRET_HYGIENE,
    title="All credentials expire soon",
    action="Plan the rotation now, preferably to federated credentials",
)
def secrets_expiring_soon(ctx: RuleContext) -> list[SecurityFinding]:
    out = []
    horizon = ctx.now + timedelta(days=ctx.cfg.expiring_soon_days)
    for entity, app in _app_entities(ctx):
        active = _active(_credentials(app), ctx.now)
        soon = [c for c in active if c["end"] and c["end"] <= horizon]
        # only a problem if nothing valid will remain after they expire
        if not soon or any(c["end"] is None or c["end"] > horizon for c in active):
            continue
        days_left = min((c["end"] - ctx.now).days for c in soon)
        end_date = (ctx.now + timedelta(days=180)).date().isoformat()
        rotation = [
            "# or, if a new secret is unavoidable, store it in Key Vault so it never reaches the terminal:",
            _hold(f"az keyvault secret set --vault-name \"<VAULT_NAME>\" --name rotated-{entity.app_id} -o none "
                  f"--value \"$(az ad app credential reset --id {entity.app_id} --append --display-name rotated "
                  f"--end-date {end_date} --query password -o tsv)\""),
        ] if any(c["kind"] == "client_secret" for c in soon) else [
            "# or upload the renewed certificate, keeping the current one until the workload has switched:",
            f"az ad app credential reset --id {entity.app_id} --append --cert \"@<NEW_CERTIFICATE_FILE>\"",
        ]
        out.append(ctx.finding(
            entity, "NHI-SEC-005",
            category=FindingCategory.SECRET_HYGIENE,
            severity=Severity.LOW,
            title=f"All credentials expire within {days_left} days",
            description=(
                f"Every valid credential of '{entity.display_name}' expires within {ctx.cfg.expiring_soon_days} "
                "days and no replacement exists yet. Unplanned expiry causes outages and rushed, insecure rotations."
            ),
            attack_path_context=(
                "Emergency rotations are when secrets get pasted into tickets and chats, or issued with "
                "multi-year lifetimes 'to avoid this next time'."
            ),
            remediation_cli="\n".join(_federation_steps(entity.app_id, []) + rotation),
            evidence={"days_until_expiry": days_left,
                      "credentials": [{"key_id": c["key_id"], "expires_on": _iso(c["end"])} for c in soon]},
        ))
    return out


# --------------------------------------------------------------------------- #
# dormant_nhi
# --------------------------------------------------------------------------- #


def _dormancy_targets(ctx: RuleContext) -> list[tuple[NHIEntity, list[dict[str, Any]], str]]:
    """(entity holding live credentials, its active credentials, related SP id).

    The sign-in report only covers sign-ins into THIS tenant, so app
    registrations without a local service principal or open to other tenants /
    personal accounts are skipped: their real usage is not observable here.
    Disabled identities cannot sign in, Microsoft first-party service principals
    are not the tenant's to disable, and managed identities hold a platform
    certificate that is rotated automatically, so none of them is a target.
    """
    targets = []
    for entity, app in _app_entities(ctx):
        sp_id = entity.raw_metadata.get("service_principal_id")
        if not sp_id or not entity.is_enabled or app.get("signInAudience") in MULTI_TENANT_AUDIENCES:
            continue
        creds = _active(_credentials(app), ctx.now)
        if creds:
            targets.append((entity, creds, sp_id))
    for entity in _sp_entities(ctx):
        if entity.raw_metadata.get("is_tenant_owned_app"):
            continue  # covered through its app registration
        if (not entity.is_enabled or entity.raw_metadata.get("is_microsoft_first_party")
                or _is_managed_identity(entity)):
            continue
        creds = _active(_credentials(ctx.inv.sp_by_id[entity.entity_id]), ctx.now)
        if creds:
            targets.append((entity, creds, entity.entity_id))
    return targets


def _disable_cmds(entity: NHIEntity, sp_id: str, creds: list[dict[str, Any]]) -> str:
    deletes = [
        _app_cred_delete(entity.app_id, c) if entity.entity_type is EntityType.APP_REGISTRATION
        else _sp_cred_delete(entity.entity_id, c)
        for c in creds
    ]
    return "\n".join([
        "# 1. Disable the identity. This is reversible: set accountEnabled=true to undo it.",
        f"az ad sp update --id {sp_id} --set accountEnabled=false",
        "# 2. After an observation period with no impact, remove its credentials:",
        *map(_hold, deletes),
    ])


@rule(
    "NHI-DORM-001", FindingCategory.DORMANT_NHI, requires="signin",
    title="Dormant identity with valid credentials",
    action="Disable the identity, then remove its credentials once nothing breaks",
)
def dormant_with_credentials(ctx: RuleContext) -> list[SecurityFinding]:
    out = []
    for entity, creds, sp_id in _dormancy_targets(ctx):
        last = entity.last_sign_in
        if last is None:
            continue
        idle = (ctx.now - last).days
        if idle < ctx.cfg.dormant_days:
            continue
        privileged = sp_id in ctx.privileged_sp_ids
        out.append(ctx.finding(
            entity, "NHI-DORM-001",
            category=FindingCategory.DORMANT_NHI,
            severity=Severity.HIGH if privileged else Severity.MEDIUM,
            title=f"Dormant for {idle} days with {len(creds)} valid credential(s)",
            description=(
                f"'{entity.display_name}' last authenticated {idle} days ago but still holds {len(creds)} valid "
                "credential(s). Nobody would notice if it started signing in again."
            ),
            attack_path_context=(
                "Dormant identities with live credentials are prime targets: their activity is not baselined, "
                "so an attacker using a leaked secret blends in. " + _blast_radius(ctx, sp_id)
            ),
            remediation_cli=_disable_cmds(entity, sp_id, creds),
            evidence={"last_sign_in": _iso(last), "days_inactive": idle, "threshold_days": ctx.cfg.dormant_days,
                      "active_credentials": len(creds), "privileged": privileged},
        ))
    return out


@rule(
    "NHI-DORM-002", FindingCategory.DORMANT_NHI, requires="signin",
    title="Never-used identity with valid credentials",
    action="Confirm the business purpose; otherwise disable it, then remove its credentials",
)
def never_used_with_credentials(ctx: RuleContext) -> list[SecurityFinding]:
    out = []
    for entity, creds, sp_id in _dormancy_targets(ctx):
        if entity.last_sign_in is not None:
            continue
        age = (ctx.now - entity.created_datetime).days if entity.created_datetime else None
        if age is not None and age < ctx.cfg.dormant_days:
            continue
        privileged = sp_id in ctx.privileged_sp_ids
        out.append(ctx.finding(
            entity, "NHI-DORM-002",
            category=FindingCategory.DORMANT_NHI,
            severity=Severity.HIGH if privileged else Severity.MEDIUM,
            title="Never signed in, yet holds valid credentials",
            description=(
                f"'{entity.display_name}' has no recorded sign-in"
                + (f" in the {age} days since it was created" if age is not None else "")
                + f" but holds {len(creds)} valid credential(s). It is either abandoned or not yet in use."
            ),
            attack_path_context=(
                "Unused identities with credentials and permissions are free attack surface: first use by an "
                "attacker raises no anomaly because there is no history. " + _blast_radius(ctx, sp_id)
            ),
            remediation_cli=_disable_cmds(entity, sp_id, creds),
            evidence={"created": _iso(entity.created_datetime), "age_days": age,
                      "active_credentials": len(creds), "privileged": privileged},
        ))
    return out


# --------------------------------------------------------------------------- #
# excessive_graph_permissions
# --------------------------------------------------------------------------- #


def _revoke_app_roles(sp_id: str, assignments: list[dict[str, str]]) -> str:
    return "\n".join(
        f"az rest --method DELETE --url {GRAPH_API}/servicePrincipals/{sp_id}/appRoleAssignments/{a['assignment_id']}"
        f"  # {a['permission']}"
        for a in assignments
    )


@rule(
    "NHI-PERM-001", FindingCategory.EXCESSIVE_GRAPH_PERMISSIONS, requires="graph_permissions",
    title="Tenant-takeover Graph permissions",
    action="Revoke the permission and grant a least-privileged alternative",
)
def tier0_graph_permissions(ctx: RuleContext) -> list[SecurityFinding]:
    out = []
    for entity in _sp_entities(ctx):
        hits = [p for p in ctx.graph_perms.get(entity.entity_id, []) if p["permission"] in TIER0_GRAPH_PERMISSIONS]
        if not hits:
            continue
        names = sorted({p["permission"] for p in hits})
        out.append(ctx.finding(
            entity, "NHI-PERM-001",
            category=FindingCategory.EXCESSIVE_GRAPH_PERMISSIONS,
            severity=Severity.CRITICAL,
            title=f"Tenant-takeover Graph permission: {', '.join(names)}",
            description=(
                f"'{entity.display_name}' holds Microsoft Graph application permission(s) {', '.join(names)}. "
                "Application permissions apply tenant-wide with no user in the loop."
            ),
            attack_path_context=(
                "Compromise of this identity is equivalent to Global Administrator: "
                + "; ".join(f"{n} {TIER0_GRAPH_PERMISSIONS[n]}" for n in names) + "."
                + (" The identity has no owner, so no one is accountable for it." if entity.is_orphaned else "")
            ),
            remediation_cli=_revoke_app_roles(entity.entity_id, hits),
            evidence={"permissions": names, "assignments": hits, "orphaned": entity.is_orphaned},
        ))
    return out


@rule(
    "NHI-PERM-002", FindingCategory.EXCESSIVE_GRAPH_PERMISSIONS, requires="graph_permissions",
    title="Tenant-wide data access",
    action="Scope access down with resource-specific consent or access policies",
)
def high_impact_graph_permissions(ctx: RuleContext) -> list[SecurityFinding]:
    out = []
    for entity in _sp_entities(ctx):
        hits = [p for p in ctx.graph_perms.get(entity.entity_id, []) if p["permission"] in HIGH_IMPACT_GRAPH_PERMISSIONS]
        if not hits:
            continue
        names = sorted({p["permission"] for p in hits})
        out.append(ctx.finding(
            entity, "NHI-PERM-002",
            category=FindingCategory.EXCESSIVE_GRAPH_PERMISSIONS,
            severity=Severity.HIGH,
            title=f"Tenant-wide data access: {', '.join(names)}",
            description=(
                f"'{entity.display_name}' can {'; '.join(HIGH_IMPACT_GRAPH_PERMISSIONS[n] for n in names)}. "
                "Consider resource-specific consent or Exchange application access policies to scope it down."
            ),
            attack_path_context=(
                "A stolen token for this identity gives silent, tenant-wide access to business data: "
                "bulk exfiltration of mail/files and impersonation without touching any user account or MFA."
            ),
            remediation_cli=_revoke_app_roles(entity.entity_id, hits),
            evidence={"permissions": names, "assignments": hits},
        ))
    return out


@rule(
    "NHI-PERM-003", FindingCategory.EXCESSIVE_GRAPH_PERMISSIONS, requires="directory_roles",
    title="Privileged Entra directory role",
    action="Remove the role or replace it with a narrowly scoped one",
)
def privileged_directory_roles(ctx: RuleContext) -> list[SecurityFinding]:
    out = []
    for entity in _sp_entities(ctx):
        roles = ctx.dir_roles.get(entity.entity_id)
        if not roles:
            continue
        top = max(roles, key=lambda r: r["severity"].rank)
        sev = top["severity"]
        names = sorted({r["role"] for r in roles})
        out.append(ctx.finding(
            entity, "NHI-PERM-003",
            category=FindingCategory.EXCESSIVE_GRAPH_PERMISSIONS,
            severity=sev,
            title=f"Privileged Entra role: {', '.join(names)}",
            description=(
                f"Service principal '{entity.display_name}' is a permanent member of {', '.join(names)}. "
                "Workload identities are excluded from most MFA and Conditional Access controls."
            ),
            attack_path_context=(
                f"Anyone who can authenticate as this identity operates as {top['role']}"
                + (" and can take over the entire tenant." if sev is Severity.CRITICAL else
                   ", limited to the administrative unit or application of the assignment."
                   if sev is Severity.MEDIUM else ", with control over a sensitive slice of the tenant.")
            ),
            remediation_cli="\n".join(
                f"az rest --method DELETE --url {GRAPH_API}/roleManagement/directory/roleAssignments/{r['assignment_id']}"
                f"  # {r['role']}"
                for r in roles
            ),
            evidence={"roles": [{k: (v.value if isinstance(v, Severity) else v) for k, v in r.items()} for r in roles]},
        ))
    return out


# --------------------------------------------------------------------------- #
# azure_rbac_privilege
# --------------------------------------------------------------------------- #


@rule(
    "NHI-RBAC-001", FindingCategory.AZURE_RBAC_PRIVILEGE, requires="azure",
    title="Azure access-control role",
    action="Remove Owner / User Access Administrator; grant narrower roles",
)
def azure_access_control_roles(ctx: RuleContext) -> list[SecurityFinding]:
    out = []
    for entity in _sp_entities(ctx):
        hits = [a for a in ctx.azure_roles.get(entity.entity_id, [])
                if a["roleName"] in AZURE_ACCESS_CONTROL_ROLES and a["level"] != "resource"]
        if not hits:
            continue
        broad = [a for a in hits if a["level"] in {"root", "management_group", "subscription"}]
        out.append(ctx.finding(
            entity, "NHI-RBAC-001",
            category=FindingCategory.AZURE_RBAC_PRIVILEGE,
            severity=Severity.CRITICAL if broad else Severity.HIGH,
            title=f"Azure {hits[0]['roleName']} on {len(hits)} scope(s)",
            description=(
                f"'{entity.display_name}' holds role-assignment-capable Azure roles "
                f"({', '.join(sorted({a['roleName'] for a in hits}))}) at "
                f"{', '.join(sorted({a['level'].replace('_', ' ') for a in hits}))} scope."
            ),
            attack_path_context=(
                "These roles can grant any role to any principal. A compromised workload can make an attacker "
                "identity Owner, read Key Vault secrets, run commands on VMs and pivot to every managed identity "
                "in scope — lateral movement from one leaked secret to the whole Azure estate."
            ),
            remediation_cli="\n".join(f"az role assignment delete --ids {a['id']}" for a in hits),
            evidence={"assignments": [{"role": a["roleName"], "scope": a["scope"], "level": a["level"],
                                       "assignment_id": a["id"]} for a in hits]},
        ))
    return out


@rule(
    "NHI-RBAC-002", FindingCategory.AZURE_RBAC_PRIVILEGE, requires="azure",
    title="Broad Azure Contributor",
    action="Re-scope Contributor to the resource groups actually needed",
)
def azure_broad_contributor(ctx: RuleContext) -> list[SecurityFinding]:
    out = []
    for entity in _sp_entities(ctx):
        hits = [a for a in ctx.azure_roles.get(entity.entity_id, [])
                if a["roleName"] == "Contributor" and a["level"] in {"root", "management_group", "subscription"}]
        if not hits:
            continue
        out.append(ctx.finding(
            entity, "NHI-RBAC-002",
            category=FindingCategory.AZURE_RBAC_PRIVILEGE,
            severity=Severity.HIGH,
            title=f"Contributor on {len(hits)} subscription-level scope(s)",
            description=(
                f"'{entity.display_name}' is Contributor at subscription or management-group scope. "
                "Pipelines rarely need more than a few resource groups."
            ),
            attack_path_context=(
                "Contributor can deploy and modify any resource: run code on VMs and Automation accounts, read "
                "storage keys, and attach privileged managed identities to attacker-controlled resources."
            ),
            remediation_cli="\n".join([
                "# 1. Grant Contributor only where it is needed (repeat for each resource group):",
                f"az role assignment create --assignee {entity.app_id} --role Contributor "
                "--scope \"<RESOURCE_GROUP_SCOPE>\"",
                "# 2. Confirm the workload still runs, then remove the broad assignment:",
                *[_hold(f"az role assignment delete --ids {a['id']}") for a in hits],
            ]),
            evidence={"assignments": [{"role": a["roleName"], "scope": a["scope"], "level": a["level"],
                                       "assignment_id": a["id"]} for a in hits]},
        ))
    return out


# --------------------------------------------------------------------------- #
# ai_agent_governance
# --------------------------------------------------------------------------- #


def _agents(ctx: RuleContext) -> list[NHIEntity]:
    return [e for e in ctx.inv.entities if e.entity_type is EntityType.AI_AGENT]


@rule(
    "NHI-AGENT-001", FindingCategory.AI_AGENT_GOVERNANCE,
    title="Orphaned AI agent",
    action="Assign an accountable owner or, for Entra Agent ID identities, a sponsor",
)
def orphaned_agent(ctx: RuleContext) -> list[SecurityFinding]:
    out = []
    for entity in _agents(ctx):
        if not entity.is_orphaned:
            continue
        app_obj = entity.raw_metadata.get("application_object_id")
        agent_id = "entra_agent_id" in entity.raw_metadata.get("agent_classification_signals", [])
        if agent_id:
            remediation = (
                f"az rest --method POST --url '{GRAPH_BETA}/servicePrincipals/{entity.entity_id}"
                f"/microsoft.graph.agentIdentity/sponsors/$ref' "
                f"--body '{{\"@odata.id\":\"{GRAPH_BETA}/directoryObjects/<SPONSOR_OBJECT_ID>\"}}'"
            )
        elif app_obj:
            remediation = f"az ad app owner add --id {entity.app_id} --owner-object-id \"<OWNER_OBJECT_ID>\""
        else:
            remediation = (
                f"az rest --method POST --url '{GRAPH_API}/servicePrincipals/{entity.entity_id}/owners/$ref' "
                f"--body '{{\"@odata.id\":\"{GRAPH_API}/directoryObjects/<OWNER_OBJECT_ID>\"}}'"
            )
        out.append(ctx.finding(
            entity, "NHI-AGENT-001",
            category=FindingCategory.AI_AGENT_GOVERNANCE,
            severity=Severity.CRITICAL if entity.entity_id in ctx.privileged_sp_ids else Severity.HIGH,
            title="Orphaned AI agent: no accountable owner",
            description=(
                f"AI agent '{entity.display_name}' has "
                + ("no owner or sponsor. " if agent_id else "no human owner on its service principal or app registration. ") +
                "No one reviews its permissions, prompts, tools or behaviour."
            ),
            attack_path_context=(
                "Autonomous agents act on untrusted input (mail, documents, chats). Without an owner, prompt-"
                "injection abuse or permission creep goes unnoticed and there is nobody to page during an incident."
            ),
            remediation_cli=remediation,
            evidence={"classification_signals": entity.raw_metadata.get("agent_classification_signals", []),
                      "permissions": sorted(ctx.perms(entity))},
        ))
    return out


@rule(
    "NHI-AGENT-002", FindingCategory.AI_AGENT_GOVERNANCE, requires="graph_permissions",
    title="AI agent with excessive agency",
    action="Replace tenant-wide application permissions with delegated or scoped access",
)
def agent_excessive_agency(ctx: RuleContext) -> list[SecurityFinding]:
    out = []
    for entity in _agents(ctx):
        acting = sorted(ctx.perms(entity) & AGENT_ACTION_PERMISSIONS)
        if not acting:
            continue
        out.append(ctx.finding(
            entity, "NHI-AGENT-002",
            category=FindingCategory.AI_AGENT_GOVERNANCE,
            severity=Severity.HIGH,
            title=f"AI agent with tenant-wide write/act permissions ({len(acting)})",
            description=(
                f"AI agent '{entity.display_name}' can take actions across the tenant via application "
                f"permissions: {', '.join(acting)}. Agents should use delegated, user-scoped access or "
                "resource-specific consent."
            ),
            attack_path_context=(
                "OWASP LLM06 Excessive Agency: a single injected instruction in content the agent processes can "
                "make it send mail, overwrite files or change directory objects with its own tenant-wide rights."
            ),
            remediation_cli=_revoke_app_roles(
                entity.entity_id, [p for p in ctx.graph_perms.get(entity.entity_id, []) if p["permission"] in acting]
            ),
            evidence={"action_permissions": acting},
        ))
    return out


@rule(
    "NHI-AGENT-003", FindingCategory.AI_AGENT_GOVERNANCE, requires="graph_permissions",
    title="AI agent data-exfiltration path",
    action="Remove the egress permission or split read and send capabilities",
)
def agent_exfiltration_path(ctx: RuleContext) -> list[SecurityFinding]:
    out = []
    for entity in _agents(ctx):
        perms = ctx.perms(entity)
        reads = sorted(perms & AGENT_BROAD_READ_PERMISSIONS)
        egress = sorted(perms & AGENT_EGRESS_PERMISSIONS)
        if not reads or not egress:
            continue
        out.append(ctx.finding(
            entity, "NHI-AGENT-003",
            category=FindingCategory.AI_AGENT_GOVERNANCE,
            severity=Severity.CRITICAL,
            title="AI agent can read tenant data and send it out (exfiltration path)",
            description=(
                f"AI agent '{entity.display_name}' combines broad read access ({', '.join(reads)}) with an "
                f"egress channel ({', '.join(egress)}): the 'lethal trifecta' of private data, untrusted input "
                "and external communication."
            ),
            attack_path_context=(
                "Indirect prompt injection: an attacker emails or shares a document containing instructions; the "
                f"agent reads it, collects data via {reads[0]} and exfiltrates it via {egress[0]} — no credential "
                "theft required."
            ),
            remediation_cli=_revoke_app_roles(
                entity.entity_id, [p for p in ctx.graph_perms.get(entity.entity_id, []) if p["permission"] in egress]
            ),
            evidence={"read_permissions": reads, "egress_permissions": egress},
        ))
    return out


@rule(
    "NHI-AGENT-004", FindingCategory.AI_AGENT_GOVERNANCE,
    title="AI agent using static secrets",
    action="Move the agent to a managed identity or federated credentials",
)
def agent_static_secret(ctx: RuleContext) -> list[SecurityFinding]:
    out = []
    for entity in _agents(ctx):
        app = ctx.inv.app_by_app_id.get(entity.app_id or "")
        app_secrets = [c for c in _active(_credentials(app), ctx.now) if c["kind"] == "client_secret"] if app else []
        sp_secrets = [c for c in _active(_credentials(ctx.inv.sp_by_id[entity.entity_id]), ctx.now)
                      if c["kind"] == "client_secret"]
        sources = app_secrets + sp_secrets
        if not sources:
            continue
        deletes = ([_app_cred_delete(entity.app_id, c) for c in app_secrets]
                   + [_sp_cred_delete(entity.entity_id, c) for c in sp_secrets])
        steps = (
            ["# Best option on Azure: host the agent with a managed identity. Otherwise:",
             *_federation_steps(entity.app_id, deletes)]
            if app else
            ["# This app is registered in another tenant: ask its vendor how to authenticate without a secret.",
             "# Once it no longer uses the secret, delete it:", *map(_hold, deletes)]
        )
        out.append(ctx.finding(
            entity, "NHI-AGENT-004",
            category=FindingCategory.AI_AGENT_GOVERNANCE,
            severity=Severity.MEDIUM,
            title="AI agent authenticates with a static client secret",
            description=(
                f"AI agent '{entity.display_name}' uses {len(sources)} client secret(s) instead of a managed "
                "identity or workload identity federation."
            ),
            attack_path_context=(
                "Agent runtimes expose their environment to tools and code interpreters; a secret in an env var or "
                "config file can be read back through the agent itself and replayed from anywhere."
            ),
            remediation_cli="\n".join(steps),
            evidence={"client_secrets": [{"key_id": c["key_id"], "expires_on": _iso(c["end"])} for c in sources]},
        ))
    return out


@rule(
    "NHI-AGENT-005", FindingCategory.AI_AGENT_GOVERNANCE,
    title="Multi-tenant AI agent",
    action="Restrict the sign-in audience to this organization",
)
def agent_multi_tenant(ctx: RuleContext) -> list[SecurityFinding]:
    out = []
    for entity in _agents(ctx):
        app = ctx.inv.app_by_app_id.get(entity.app_id or "")
        audience = (app or {}).get("signInAudience")
        if audience not in MULTI_TENANT_AUDIENCES:
            continue
        out.append(ctx.finding(
            entity, "NHI-AGENT-005",
            category=FindingCategory.AI_AGENT_GOVERNANCE,
            severity=Severity.HIGH if ctx.perms(entity) else Severity.MEDIUM,
            title="AI agent registered as multi-tenant",
            description=(
                f"The app behind AI agent '{entity.display_name}' accepts sign-ins from any Entra tenant "
                f"(signInAudience={audience})."
            ),
            attack_path_context=(
                "Its credentials authenticate in every tenant that consented to it; a compromise of this agent is "
                "a supply-chain compromise for all of them, and anyone can attempt consent phishing with its name."
            ),
            remediation_cli=f"az ad app update --id {entity.app_id} --sign-in-audience AzureADMyOrg",
            evidence={"sign_in_audience": audience},
        ))
    return out

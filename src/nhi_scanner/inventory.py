"""Normalise a raw ``TenantSnapshot`` into the ``NHIEntity`` inventory.

Modelling choices (mirrors how Entra actually stores things):
  * an app registration (application object) and its service principal are two
    entities, cross-linked through ``raw_metadata``. Secrets usually live on the
    application; permissions and role assignments live on the service principal.
  * the service principal is the identity that acts, so it is the one typed
    ``ai_agent`` / ``managed_identity``.
  * a service principal's ``owners`` include the owners of its app registration:
    in Zetah terms they are accountable for the identity either way.
  * Microsoft first-party service principals are only inventoried when someone
    has attached credentials to them (a known persistence technique).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from .models import EntityType, NHIEntity
from .snapshot import TenantSnapshot, parse_graph_datetime

MICROSOFT_TENANTS = {
    "f8cdef31-a31e-4b4a-93e4-5f571e91255a",  # Microsoft Services
    "72f988bf-86f1-41af-91ab-2d7cd011db47",  # Microsoft Corp
}

_AGENT_TAGS = {"agentidentity", "aiagent", "ai-agent", "copilotstudio", "power-virtual-agents", "azureaiagent"}
# Words that identify AI software on their own...
_AI_NAME = re.compile(
    r"^(gpt\w*|chatgpt|openai|anthropic|claude|copilot|llm|chatbot|agentic|aiagent|langchain|langgraph|crewai|autogen"
    r"|mcp|gemini|mistral)s?$"
)
# ...and words that also name ordinary software (monitoring agents, mail bots), so they need an AI word beside them.
_AGENT_WORDS = {"agent", "agents", "assistant", "assistants", "bot", "bots"}
_AI_CONTEXT_WORDS = {"ai", "genai", "foundry"}


def _name_words(name: str) -> set[str]:
    """Lower-case words of a name, also split at camelCase: 'SalesAIAgent' -> sales, ai, agent, salesaiagent."""
    split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", " ", name)
    return set(re.findall(r"[a-z0-9]+", name.lower())) | set(re.findall(r"[a-z0-9]+", split.lower()))


def _owner_refs(obj: dict[str, Any], people_only: bool = False) -> list[str]:
    return [
        o.get("userPrincipalName") or o["id"]
        for o in obj.get("owners") or []
        if not (people_only and o.get("@odata.type", "").lower().endswith("serviceprincipal"))
    ]


def _sponsor_refs(sp: dict[str, Any]) -> list[str]:
    return [s.get("userPrincipalName") or s.get("displayName") or s["id"] for s in sp.get("sponsors") or []]


def agent_signals(sp: dict[str, Any], app: Optional[dict[str, Any]]) -> list[str]:
    """Why (if at all) we believe this service principal is an AI agent.

    Entra Agent ID objects are recognised directly; everything else is a
    heuristic and the matched signals are kept as evidence for the analyst.
    """
    signals: list[str] = []
    odata_type = sp.get("@odata.type", "").lower()
    # Microsoft sets servicePrincipalType to "ServiceIdentity" for every agent identity
    if odata_type.endswith("agentidentity") or sp.get("servicePrincipalType") in ("ServiceIdentity", "AgentIdentity"):
        signals.append("entra_agent_id")
    elif odata_type.endswith("agentidentityblueprintprincipal"):
        signals.append("entra_agent_blueprint")
    tags = {t.lower() for t in (sp.get("tags") or []) + ((app or {}).get("tags") or [])}
    for tag in sorted(tags & _AGENT_TAGS):
        signals.append(f"tag:{tag}")
    words = _name_words(sp.get("displayName") or "")
    ai_words = sorted(w for w in words if _AI_NAME.match(w))
    if ai_words:
        signals.append(f"name:{ai_words[0]}")
    elif (words & _AI_CONTEXT_WORDS) and (words & _AGENT_WORDS):
        signals.append(f"name:{min(words & _AI_CONTEXT_WORDS)} {min(words & _AGENT_WORDS)}")
    return signals


@dataclass
class Inventory:
    """Entities plus the lookups the rule engine needs."""

    entities: list[NHIEntity]
    by_id: dict[str, NHIEntity] = field(default_factory=dict)
    app_by_app_id: dict[str, dict[str, Any]] = field(default_factory=dict)  # raw application objects
    sp_by_id: dict[str, dict[str, Any]] = field(default_factory=dict)  # raw service principals
    sp_entity_by_app_id: dict[str, NHIEntity] = field(default_factory=dict)
    app_entity_by_app_id: dict[str, NHIEntity] = field(default_factory=dict)


def build_inventory(snap: TenantSnapshot) -> Inventory:
    apps_by_app_id = {a["appId"]: a for a in snap.applications}
    signin = snap.signin_activity or {}
    sps_by_app_id: dict[str, dict[str, Any]] = {}
    entities: list[NHIEntity] = []

    for sp in snap.service_principals:
        first_party = sp.get("appOwnerOrganizationId") in MICROSOFT_TENANTS
        has_sp_creds = bool(sp.get("passwordCredentials") or sp.get("keyCredentials"))
        if first_party and not has_sp_creds:
            continue
        app = apps_by_app_id.get(sp.get("appId"))
        sps_by_app_id[sp["appId"]] = sp

        sp_type = sp.get("servicePrincipalType") or "Application"
        signals = agent_signals(sp, app)
        if signals:
            etype = EntityType.AI_AGENT
        elif sp_type == "ManagedIdentity":
            etype = EntityType.MANAGED_IDENTITY
        else:
            etype = EntityType.SERVICE_PRINCIPAL

        is_agent_id = "entra_agent_id" in signals
        sponsors = _sponsor_refs(sp) if "sponsors" in sp else None
        # Accountability for an agent means a person: another service principal cannot answer for it
        people_only = etype is EntityType.AI_AGENT
        owners = list(dict.fromkeys(
            _owner_refs(sp, people_only) + (_owner_refs(app, people_only) if app else []) + (sponsors or [])
        ))
        owner_org = sp.get("appOwnerOrganizationId")
        raw: dict[str, Any] = {
            "servicePrincipalType": sp_type,
            "publisherName": sp.get("publisherName"),
            "appOwnerOrganizationId": sp.get("appOwnerOrganizationId"),
            "tags": sp.get("tags") or [],
            "is_microsoft_first_party": first_party,
            "is_tenant_owned_app": app is not None,
            # Enterprise apps published by another organization have their owners in that tenant
            "is_external_app": app is None and not is_agent_id and owner_org is not None and owner_org != snap.tenant_id,
            "application_object_id": app["id"] if app else None,
            "sp_credential_count": len(sp.get("passwordCredentials") or []) + len(sp.get("keyCredentials") or []),
        }
        if signals:
            raw["agent_classification_signals"] = signals
        if is_agent_id:
            raw["agent_identity_blueprint_id"] = sp.get("agentIdentityBlueprintId")
            raw["sponsors"] = sponsors or []
            raw["sponsors_unknown"] = sponsors is None
        if sp_type == "ManagedIdentity":
            raw["azure_resource_id"] = next(
                (n for n in sp.get("alternativeNames") or [] if n.startswith("/subscriptions/")), None
            )
            raw["managed_identity_kind"] = (
                "user_assigned" if any(n == "isExplicit=True" for n in sp.get("alternativeNames") or []) else "system_assigned"
            )

        entities.append(
            NHIEntity(
                entity_id=sp["id"],
                app_id=sp.get("appId"),
                display_name=sp.get("displayName") or sp["id"],
                entity_type=etype,
                created_datetime=parse_graph_datetime(app.get("createdDateTime")) if app else None,
                last_sign_in=signin.get(sp.get("appId")),
                is_enabled=sp.get("accountEnabled", True),
                owners=owners,
                raw_metadata=raw,
            )
        )

    for app in snap.applications:
        sp = sps_by_app_id.get(app["appId"])
        entities.append(
            NHIEntity(
                entity_id=app["id"],
                app_id=app["appId"],
                display_name=app.get("displayName") or app["id"],
                entity_type=EntityType.APP_REGISTRATION,
                created_datetime=parse_graph_datetime(app.get("createdDateTime")),
                last_sign_in=signin.get(app["appId"]),
                # application objects have no enabled flag; mirror the local SP when there is one
                is_enabled=sp.get("accountEnabled", True) if sp else True,
                owners=_owner_refs(app),
                raw_metadata={
                    "signInAudience": app.get("signInAudience"),
                    "publisherDomain": app.get("publisherDomain"),
                    "tags": app.get("tags") or [],
                    "service_principal_id": sp["id"] if sp else None,
                    "password_credential_count": len(app.get("passwordCredentials") or []),
                    "certificate_credential_count": len(app.get("keyCredentials") or []),
                },
            )
        )

    inv = Inventory(entities=entities)
    inv.by_id = {e.entity_id: e for e in entities}
    inv.app_by_app_id = apps_by_app_id
    inv.sp_by_id = {sp["id"]: sp for sp in snap.service_principals}
    for e in entities:
        if e.entity_type is EntityType.APP_REGISTRATION:
            inv.app_entity_by_app_id[e.app_id] = e
        elif e.app_id:
            inv.sp_entity_by_app_id[e.app_id] = e
    return inv

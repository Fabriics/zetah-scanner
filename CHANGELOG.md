# Changelog

## Unreleased

**Large tenants (T-14).** `--demo --demo-size N` generates a synthetic tenant of about N identities. On 100,000
identities the full scan (rules, JSON, PDF) takes about 30 seconds with a peak of about 2 GB on a laptop, down from
over 6 GB: the payload is re-validated one part at a time and written to disk in parts, byte for byte as before. The
PDF and the console list the most important rows (300 in the plan, 60 in detail, 1,000 identities) and count the rest
by rule; the JSON always holds everything. The collector asks for pages of 999 objects, reads federated credentials
from one expanded listing instead of one request per app, and does the remaining per-object reads eight at a time,
still only with `GET` (Graph's `$batch` is a POST). Throttling (429) gets its own retry budget, up to ten minutes of
waiting per request, and `Retry-After` is bounded. `tests/scale_benchmark.py` measures collection against a simulated
Graph with latency and throttling.

**Security review (26/11/2026).** The scanner was attacked from every side it has; `tests/test_attacks.py` keeps
every attack in the suite.
- Remediation commands are checked by an allowlist, not a list of dangers: only `az ad app`, `az ad sp`,
  `az role assignment` and `az rest`; no shell syntax outside quotes; `az rest` only towards Microsoft Graph or
  Azure Resource Manager, never with `--resource`, custom headers or an output file; no argument that loads a file.
  The old check let through `az` commands that could send a token to another host or upload a local file.
- The check runs again when the PDF is written and when a saved payload is loaded with `--from-json`: an edited
  payload can no longer put a live command in the report as if Zetah had suggested it.
- The collector no longer follows redirects, stops when a paging link repeats or pages never end, treats a response
  that is not a JSON object as a read that failed (a warning, not a crash), and checks every object id from a
  response before it becomes part of a URL.
- A malformed date reads as unknown instead of stopping the scan; `--dormant-days` must be between 1 and 3650.
- The PDF and the console cap the length of one value and the lines of one finding: a very long text or thousands of
  credentials on one identity no longer stop the report or take minutes. The JSON keeps everything.

**Third-party apps by vendor (T-34).** Apps published by another organization sign in with credentials that live in
the publisher's tenant: they cannot be seen, rotated or revoked from yours. The PDF has a new section that groups them
by the tenant that holds those credentials, with each app's status, last sign-in, tenant-wide application permissions
(those that can write or send highlighted) and delegated consents. The console prints a one-line summary.

**New check**
- `NHI-PERM-004`: a third-party app with application permissions valid across the tenant. Critical with a
  tenant-takeover Graph permission, high with mail, files or sites, medium otherwise. The finding names the vendor's
  tenant and verified publisher, the other apps of the same vendor, the account status and the last sign-in. Every
  suggested command is commented out: revoking breaks the vendor's integration. OWASP NHI3 and NHI5. A third-party
  app with a tenant-takeover or data permission also keeps its `NHI-PERM-001` or `NHI-PERM-002` finding: one says
  what the permission allows, the other who holds the credentials.

**Reads.** Application permissions on Exchange Online (`full_access_as_app`, `Exchange.ManageAsApp`, `Mail.*`) and
SharePoint Online (`Sites.FullControl.All`, ...) are now read, with the same `Application.Read.All` permission and only
`GET` requests. They are not listed in the identity record yet: the record keeps its Microsoft Graph section.

## 0.2.0 (2026-11-16)

The scanner now describes every non-human identity, not only the risky ones, and checks the paths that recent
incidents used: consents to AI clients, GitHub Actions trusts and AI accounts that still accept static keys.

**The identity record (contract version 2, #4).** Every identity carries a record of ten sections: profile, owners,
sponsors, credentials one by one, federated credentials, Microsoft Graph application permissions, delegated
permissions, Entra roles, Azure roles and activity. Each section says whether it was read, could not be read or does
not apply, and from which Graph or Azure Resource Manager read and when. "Not read" is never "empty". AI accounts
appear as a new entity type, `api_key`. Version 1 payloads are still accepted.

**New checks**
- `NHI-AGENT-006`: an AI client whose delegated consents let it read users' data and send it out (#5).
- `NHI-AGENT-008`: an AI client with `offline_access` on mail, files, chats or write scopes (#5). Both go up one
  level when a user who consented holds a privileged Entra role across the tenant (#8).
- `NHI-SEC-006`: a GitHub Actions federated credential bound too loosely (any pull request, a whole repository, a
  non-main branch, tags, an environment whose protection is not visible, a flexible credential), on app
  registrations and user-assigned managed identities (#6).
- `NHI-SEC-007`: an Azure OpenAI or AI Services account that still accepts static API keys, with the identities whose
  roles can list those keys (#7). Keys are never listed: listing them is an action.

**OWASP (#10).** Every rule names the entries of the OWASP Top 10 Non-Human Identities Risks 2025 and of the OWASP Top
10 for Agentic Applications 2026 its findings are an instance of. Findings carry them in the `owasp` field; the PDF,
the console and the README show them.

**Hardening against a hostile tenant (#9).** Names, descriptions and other values come from the tenant and are
treated as hostile: the access token is only ever sent to Microsoft Graph and Azure Resource Manager, even when a
paging link points elsewhere; suggested commands carry only identifiers that pass a strict check, and steps that could
break a workload stay commented on every line; control characters and terminal escape sequences are removed from the
console and the PDF.

**Other**
- When the scanner cannot sign in, its help suggests `az login`, a managed identity or workload identity federation,
  no longer a client secret.

New permission to read: `Reader` on Azure now also covers AI accounts and the federated credentials of user-assigned
managed identities. The read-only promise is unchanged: only `GET` requests, results stay on your machine.

## 0.1.1 (2026-11-05)

Sponsors of Entra Agent ID identities read from Microsoft Graph v1.0; the service principal publisher read from a
field Graph v1.0 returns (#1); pypdf 6.21.4 (#2).

## 0.1.0 (2026-10-30)

First release: the free, read-only Entra Agent ID readiness check, with inventory, hygiene score and PDF report.

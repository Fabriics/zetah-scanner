# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's private reporting instead:
**Security** tab of this repository → **Report a vulnerability**.

Include what you found, how to reproduce it, and the impact you expect. You will get an
acknowledgement within a few days.

## Scope

`zetah-scanner` only reads from Microsoft Graph and Azure Resource Manager and writes local files.
Reports about the scanner sending data anywhere unexpected, issuing non-read requests, mishandling
credentials, or producing reports that could be used to inject content are especially welcome.

## Handling scan results

Scan outputs (PDF, JSON) describe identities, privileges and attack paths in your tenant. Treat them
as confidential and do not attach real scan results to public issues.

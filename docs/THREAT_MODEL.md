# Threat model

## Assets

Keycloak credentials, session cookies, client secrets, HR attributes, approval records, and the audit chain.

## Boundaries

The browser holds no client secret and no long-lived token. IdentityGate, Finance, and Projects terminate OIDC on the server. The provisioner cannot use the master realm. Downstream SCIM is a separate token.

## Abuse cases the demonstration is built to resist

- Missing, expired, wrong-audience, wrong-issuer, or unsigned tokens are rejected.
- A standard user calling a lifecycle route receives 403.
- Cookie mutations without the CSRF header receive 403.
- A requester cannot approve their own access request, and a reviewer cannot certify their own entitlement.
- Redirect URIs are the exact callback URLs in the realm, not wildcards.
- Logs and stored SCIM attempts redact bearer tokens and passwords.

## Accepted limitations

- `start-dev` does not terminate TLS. Cookies are not marked Secure.
- A stolen 300-second access token remains usable until expiry even after logout, except where an application forces a refresh.
- The audit hash chain does not survive a hostile database administrator.
- The downstream directory is an in-process SQLite service with a bearer token. It is an interoperability target, not a hardened enterprise directory.
- Bootstrap prints no secrets, but `.env` on disk is the trust store for this workstation. Do not reuse those values anywhere else.
- Findings are rule hits. They are not an intrusion verdict.

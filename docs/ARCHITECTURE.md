# Architecture

```text
Synthetic HR record
        |
        v
IdentityGate joiner / mover / leaver
        |
        +--> Keycloak SCIM /realms/northstar/scim/v2
        |         OIDC, groups, client roles, sessions, events
        |
        +--> Northstar Directory  (outbound SCIM)
        |
        +--> PostgreSQL governance records
                    |
                    v
            IdentityGate control centre

Northstar Finance and Northstar Projects
        authenticate at Keycloak and call policy.decision
```

Keycloak is authoritative for passwords, sessions, and role mappings. IdentityGate is authoritative for requests, approvals, review snapshots, findings, and control evaluations. The downstream directory is authoritative for its own user rows. A disabled Keycloak user is not the same thing as an archived governance record.

The browser never receives a client secret. IdentityGate and the sample applications keep tokens in HttpOnly cookies. The shared decision function in `policy/decision.py` is what both the API simulator and the sample applications use, so a simulated allow cannot disagree with the application.

Runtime calls to Keycloak use the `identitygate-provisioner` service account. The master administrator password is used only while `app.bootstrap` configures client secrets, the user profile, group role mappings, and the SCIM audience. After that, application code uses client credentials.

Tokens are expected from `http://localhost:8080` even when the API reaches Keycloak at `http://keycloak:8080`. Discovery from inside Docker advertises localhost, so token calls use the internal URL directly and signature checks use the public issuer.

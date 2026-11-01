# SCIM provisioning

## Inbound

The synthetic HR record is stored in `hr_employees`. The joiner sends the user to Keycloak's native SCIM API:

`http://keycloak:8080/realms/northstar/scim/v2`

The browser-facing audience configured on the provisioner is:

`http://localhost:8080/realms/northstar/scim/v2`

Authentication is client credentials for `identitygate-provisioner`. The client has full scope allowed turned off. Its service account holds realm-management roles needed to manage users, read events, and query clients. It is not a master realm administrator.

Supported operations in this integration: create, get, filter, replace, patch, deactivate, and delete users; create groups; patch group members. Keycloak 26.8 does not advertise bulk, sort, or ETag. Group members are changed with PATCH, not by sending members on POST. The interoperability panel runs those checks and reports pass or fail. A passing panel is not a certification from a standards body.

Enterprise attributes mapped through the user profile annotation `kc.scim.schema.attribute` include employee number, department, cost centre, and manager. The stable key is the employee number, stored as `externalId`. Email is not the identifier.

Every attempt stores the source id, target system, operation, HTTP status, correlation id, duration, and a redacted body. Bearer tokens and passwords are removed before storage.

## Outbound

Keycloak SCIM does not push accounts to other applications. IdentityGate compares the desired directory with Northstar Directory at `/scim/v2` and creates or updates users with an `externalId`. Reconciliation lists missing accounts, extra accounts, wrong active flags, and group or role differences. Repair is a second step after a dry run is inspected. Retries use the workflow stage record and stop after repeated failures.

The directory token is `DOWNSTREAM_SCIM_TOKEN`. The process default `directory-token` exists only so a local process without configuration can boot; Compose always sets the generated token.

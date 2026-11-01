# Testing

## Automated

```powershell
python -m pytest backend/tests scim-target/test_server.py -q --tb=short
```

`backend/tests/test_policy.py` covers decisions, birthright, mover diffs, segregation, approvals, self-review, the audit chain, and control evaluators.

`backend/tests/test_security.py` covers redaction, log filtering, bad signatures, wrong audience, wrong issuer, expiry, the `none` algorithm, and session encryption.

`backend/tests/test_api.py` covers an anonymous directory call, a cookie mutation without CSRF, and a standard user denied a leaver.

`scim-target/test_server.py` covers the downstream subset: 401, create, duplicate 409, filter, deactivate, group membership, and delete.

These tests do not start Keycloak. A green run does not prove the live realm.

## Live checks

After `docker compose up` and bootstrap:

1. `GET http://localhost:8000/api/v1/system/health` shows database, Keycloak, and downstream.
2. Sign in to Finance, then open Projects without entering the password again.
3. As Elena, `POST /api/reports` returns 201 and `POST /api/reports/R-101/approve` returns 403.
4. In IdentityGate, open Provisioning and run the SCIM checks.
5. Run a reconciliation and confirm desired and actual counts.
6. Open the finance campaign, approve one item, revoke another, and confirm the remediation status is separate from the decision.

## Scale

The seed is 50 identities. Search and directory endpoints are paginated. The graph loads one identity, or the department map, rather than every entitlement at once. No throughput numbers are published here because they were not measured on a recorded hardware run. A 500 or 5,000 user import should be timed on the machine that will host it before any capacity claim.

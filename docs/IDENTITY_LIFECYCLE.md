# Identity lifecycle

## Joiner

Validate the HR row, create or replace the Keycloak user, assign birthright groups, provision the downstream account, optionally set a required action, then read the user back. A stage that already succeeded is skipped on retry. A failed stage stays failed.

Birthright is the company directory plus the department group. Service accounts receive only the service-accounts group. Privileged roles are not added because a job title is senior. Approved extras in the seed data are written as fulfilled access requests after Keycloak confirms the assignment.

## Mover

The workflow records the entitlement diff, removes the previous department group and extra application groups, and adds the new department group. Direct client roles are cleared. Privileged access that the new department would require is not granted automatically. The stored diff is the before and after used by the lifecycle inspector.

## Leaver

The workflow sets the HR status to departed, deactivates the Keycloak user, requests session logout, removes groups and direct roles, revokes grant evidence, and sets the downstream account inactive. Verification fails the workflow if Keycloak is still enabled, groups remain, or the downstream account is still active. The account state stays `pending_deprovisioning` until that check passes. A disabled Keycloak account can still be distinguished from an archived governance row.

Session logout does not by itself prove that every previously issued 300-second access token is gone. The sample applications refresh before privileged actions to close that window for those actions.

`AUTO_EXPIRE` defaults to false so an expired contractor remains visible as a finding until an operator runs the expiry sweep.

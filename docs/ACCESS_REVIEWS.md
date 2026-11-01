# Access reviews

A campaign stores a snapshot of each entitlement: identity, application, role, grant source, and privilege flag. Later role changes do not rewrite that snapshot. Current access is read again only when a revoke is executed.

Decisions are approve, revoke, or reassign. The reviewer, reason, time, and entitlement id are stored on the decision row. A person cannot certify their own item. If the assigned reviewer is the subject, bootstrap reassigns the item.

Approve sets remediation to not required. Revoke starts removal. Removing a group also records it as suppressed so the next reconciliation does not put it back. A direct role is suppressed as `client:role`. The item stays `pending_removal` until Keycloak no longer shows the role. Success is `removal_succeeded`. If the role remains, the status is `reconciliation_pending` or `removal_failed`. An approved revocation is not displayed as a completed removal.

Campaign totals are counts of those rows. The progress percentage is reviewed items divided by snapshot items.

Access requests follow a separate path. The server chooses the approver. The requester and the target cannot approve. Privileged roles also require the security reviewer. Fulfilment writes the group or direct role, reads the effective roles back, and only then marks the request fulfilled. Time-boxed grants are revoked by the expiry sweep.

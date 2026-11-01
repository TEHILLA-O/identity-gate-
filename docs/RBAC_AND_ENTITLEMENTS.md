# RBAC and entitlements

Permissions live in `data/permission_matrix.json`. Role and group bindings live in `data/access_catalog.json`.

Northstar Finance:

- finance-reader: report:read
- finance-analyst: report:read, report:create
- finance-approver: report:read, payment:approve
- finance-admin: report:read, app:configure

Northstar Projects:

- project-reader: project:read
- project-contributor: project:read, project:write
- project-admin: project:read, project:manage

Department groups map to those client roles. Engineering receives reader and contributor. Finance receives finance-reader. Security receives project-reader and finance-reader. Sales, Human Resources, and Operations receive project-reader. Realm roles `identitygate-admin`, `identitygate-operator`, `identitygate-reviewer`, `identitygate-auditor`, and `identitygate-user` gate the governance API. Hiding a button is not the control. Each route calls `require(...)` and returns 403 when the role set does not include the permission.

Effective access walks group membership and direct client roles. Composite realm roles such as `default-roles-northstar` are not shown as application grants. The same permission reached by two paths is listed once, and both paths are kept. An effective role with no catalog path is shown as unresolved rather than dropped.

The policy simulator calls `policy.decision.decision` with the roles Keycloak last reported for that client. Finance and Projects import the same function. A denied payment approval for Elena is the expected result: she holds finance-analyst, and payment:approve requires finance-approver.

# Segregation of duties

Rules are stored in the permission matrix.

- SOD-FIN-01 is permission based. `report:create` and `payment:approve` conflict. Finance administration, which can configure the application and read reports, does not by itself create that conflict. Marcus Hale holds both analyst and approver, so the rule matches him.
- SOD-IGA-01 conflicts identitygate-admin with identitygate-auditor.
- SOD-IGA-02 conflicts identitygate-operator with identitygate-auditor.

Evaluation uses effective roles and the permissions those roles grant, not only roles assigned directly on the user.

An exception records justification, approver, compensating control, and expiry. The conflict remains visible with status `excepted`. The exception does not delete the rule match. A reviewer cannot file an exception for their own subject.

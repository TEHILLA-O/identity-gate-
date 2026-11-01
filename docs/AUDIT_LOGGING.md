# Audit logging

IdentityGate ingests Keycloak user events and admin events through the Admin API. It does not query Keycloak tables. Governance actions append their own audit rows: login, logout, joiner, mover, leaver, access request, review decision, and segregation exception.

Each row stores source, actor, target, type, time, outcome, correlation id, and a source reference. Password, token, secret, and authorization fields are redacted before insert. Ingestion is idempotent on the source reference hash.

Rows are hash-chained in insertion order. `verify_chain` walks `prev_hash` from the genesis value. A broken link is reported. The chain is tamper-evidence for the stored rows. It is not cryptographic immutability, because a party who can rewrite the database can rebuild the chain. The trust anchor is the application database.

The audit workspace can filter by actor, target, event type, and correlation id. Related lifecycle stages share a correlation id when the workflow created them. The interface does not invent a causal link when no correlation id is present.

Missing Keycloak events are visible as a gap only for the event types the realm is configured to emit. The realm enables login, logout, and admin events during bootstrap. Delivery still depends on Keycloak retaining those events.

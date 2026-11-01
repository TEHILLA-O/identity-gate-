"""Findings, segregation conflicts, control evaluation, and audit ingestion."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

from policy.audit_chain import GENESIS, link
from policy.controls import (
    account_lifecycle,
    audit_generation,
    configuration,
    deprovisioning,
    least_privilege,
    separation_of_duties,
)
from policy.decision import load_matrix
from policy.sod import evaluate
from sqlalchemy import func, select

from app.models import (
    AuditEvent,
    ControlDefinition,
    ControlEvaluation,
    GrantEvidence,
    HrEmployee,
    IdentityReference,
    LifecycleWorkflow,
    PolicyException,
    ReviewCampaign,
    ReviewItem,
    SecurityFinding,
    SegregationConflict,
)
from app.security.redact import redact
from app.util import new_id, utcnow

CONTROLS = [
    ("AC-2", "NIST SP 800-53", "Account management", "Departed identities must not retain an enabled authentication account.", "Compare HR departure status with the observed Keycloak enabled flag.", "Informative Annex A reference: 5.16 Identity management. Not a certification."),
    ("AC-3", "NIST SP 800-53", "Access enforcement", "Application APIs must reject unauthenticated calls.", "Request a protected Northstar Finance route without a session.", "Informative Annex A reference: 5.15 Access control. Not a certification."),
    ("AC-5", "NIST SP 800-53", "Separation of duties", "Configured toxic combinations must be visible.", "Evaluate effective permissions against the segregation catalogue.", "Informative Annex A reference: 5.3 Segregation of duties. Not a certification."),
    ("AC-6", "NIST SP 800-53", "Least privilege", "Privileged grants must point at an approval.", "Join privileged grant evidence to access requests.", "Informative Annex A reference: 8.2 Privileged access rights. Not a certification."),
    ("AU-2", "NIST SP 800-53", "Event logging", "Authentication and admin events must be enabled at the identity provider.", "Read the Keycloak realm event settings through the admin API.", "Informative Annex A reference: 8.15 Logging. Not a certification."),
    ("AU-12", "NIST SP 800-53", "Audit record generation", "Governance actions must produce a verifiable audit chain.", "Verify the IdentityGate hash chain over stored audit events.", "The chain is tamper-evident, not immutable. Not a certification."),
    ("AC-2(3)", "NIST SP 800-53", "Disable inactive accounts", "Leaver workflows must end with disabled downstream access.", "Read leaver workflow status and downstream active flags.", "Covers connected directories only."),
    ("IG-SVC", "IdentityGate", "Service-account governance", "Service accounts must have an owner approval on file.", "Inspect service-account grant records from the HR source.", "Does not discover unmanaged accounts outside the source."),
    ("IG-CFG", "NIST CM-6 illustrative", "Configuration settings", "OIDC clients must use exact redirect URIs.", "Read redirect URI settings from Keycloak.", "Only the Northstar clients are in scope."),
]

WEIGHTS = {"critical": 40, "high": 25, "medium": 12, "low": 5}


def seed_controls(db) -> None:
    for control_id, framework, title, objective, implementation, iso_note in CONTROLS:
        if db.get(ControlDefinition, control_id) is None:
            db.add(ControlDefinition(control_id=control_id, framework=framework, title=title, objective=objective, implementation=implementation, iso_note=iso_note, owner="helen.cho"))


def refresh_conflicts(db) -> list[SegregationConflict]:
    matrix = load_matrix()
    now = utcnow()
    exceptions = [
        {
            "rule_id": row.rule_id,
            "subject": row.subject,
            "state": row.state,
            "expires_at": row.expires_at.isoformat(),
        }
        for row in db.scalars(select(PolicyException)).all()
    ]
    seen = set()
    results = []
    identities = db.scalars(select(IdentityReference)).all()
    names = {row.employee_number: row.username for row in db.scalars(select(HrEmployee)).all()}
    for identity in identities:
        subject = names.get(identity.employee_number, identity.username)
        conflicts = evaluate(
            matrix,
            identity.effective_client_roles or {},
            identity.effective_realm_roles or [],
            subject=subject,
            exceptions=exceptions,
            now=now,
        )
        for conflict in conflicts:
            seen.add((conflict["rule_id"], subject))
            row = db.scalar(select(SegregationConflict).where(SegregationConflict.rule_id == conflict["rule_id"], SegregationConflict.subject == subject))
            if row is None:
                row = SegregationConflict(id=new_id(), rule_id=conflict["rule_id"], subject=subject, rule_version=conflict["version"], severity=conflict["severity"], status=conflict["status"], explanation=conflict["explanation"], detail=conflict, updated_at=now)
                db.add(row)
            else:
                row.status = conflict["status"]
                row.detail = conflict
                row.updated_at = now
            results.append(row)
    for row in db.scalars(select(SegregationConflict)).all():
        if (row.rule_id, row.subject) not in seen and row.status != "resolved":
            row.status = "resolved"
            row.updated_at = now
    return results


def evaluate_findings(db) -> list[SecurityFinding]:
    now = utcnow()
    people = {row.employee_number: row for row in db.scalars(select(HrEmployee)).all()}
    identities = {row.employee_number: row for row in db.scalars(select(IdentityReference)).all()}
    grants = db.scalars(select(GrantEvidence).where(GrantEvidence.revoked_at.is_(None))).all()
    from app.models import ExternalIdentityMapping

    downstream = {row.external_id: row for row in db.scalars(select(ExternalIdentityMapping)).all()}
    open_keys = set()

    def add(rule_id, severity, title, subject, application, evidence):
        application = application or ""
        open_keys.add((rule_id, subject or "", application))
        row = db.scalar(select(SecurityFinding).where(SecurityFinding.rule_id == rule_id, SecurityFinding.subject == subject, SecurityFinding.application == application))
        if row is None:
            row = SecurityFinding(id=new_id(), rule_id=rule_id, severity=severity, title=title, subject=subject, application=application, status="open", evidence=evidence, priority_score=WEIGHTS[severity], first_observed_at=now, updated_at=now)
            db.add(row)
        elif row.status in {"investigating", "acknowledged", "accepted", "remediation"}:
            row.evidence = evidence
            row.updated_at = now
        else:
            row.status = "open"
            row.evidence = evidence
            row.severity = severity
            row.priority_score = WEIGHTS[severity]
            row.updated_at = now

    for conflict in db.scalars(select(SegregationConflict).where(SegregationConflict.status == "open")).all():
        add("SOD_CONFLICT", conflict.severity if conflict.severity in WEIGHTS else "high", f"Segregation conflict {conflict.rule_id}", conflict.subject, conflict.rule_id, {"rule_id": conflict.rule_id, "explanation": conflict.explanation, "status": conflict.status})

    for grant in grants:
        person = people.get(grant.employee_number)
        if grant.privileged and not grant.access_request_id and person and person.employment_status == "active":
            add("PRIVILEGED_WITHOUT_APPROVAL", "high", f"Privileged role {grant.role_name} has no approval", person.username, grant.application, {"grant_id": grant.id, "role": grant.role_name, "source": grant.source})
        identity = identities.get(grant.employee_number)
        direct_count = sum(len(roles) for roles in (identity.direct_client_roles or {}).values()) if identity else 0
        if identity and direct_count >= 3 and person:
            add("EXCESSIVE_DIRECT_ROLES", "medium", "Excessive direct role assignments", person.username, "", {"direct_roles": direct_count})

    for person in people.values():
        identity = identities.get(person.employee_number)
        if person.classification == "privileged" and person.employment_status == "active" and identity and person.employment_type != "service":
            joined = datetime.fromisoformat(person.join_date).replace(tzinfo=timezone.utc)
            if joined < now - timedelta(days=90) and identity.last_login_at is None:
                add("DORMANT_PRIVILEGED", "medium", "Privileged account has no observed authentication", person.username, "", {"join_date": person.join_date, "basis": "No ingested login event. This is not an accusation."})
            if not identity.mfa_enrolled:
                add("PRIVILEGED_WITHOUT_MFA", "low", "Privileged account has no observed MFA credential", person.username, "", {"mfa_enrolled": False})
        if person.employment_type == "contractor" and person.access_expires_at and identity and identity.kc_enabled:
            expiry = datetime.fromisoformat(person.access_expires_at.replace("Z", "+00:00"))
            if expiry <= now:
                add("EXPIRED_CONTRACTOR", "high", "Contractor access is past its expiry and the account is enabled", person.username, "", {"access_expires_at": person.access_expires_at})
        if person.employment_status == "departed":
            mapping = downstream.get(person.employee_number)
            if mapping and mapping.active:
                add("DEPARTED_DOWNSTREAM_ACTIVE", "critical", "Departed identity is still active downstream", person.username, "northstar-directory", {"downstream_id": mapping.resource_id})
        if identity and identity.kc_enabled is False and identity.session_count:
            add("DISABLED_WITH_SESSION", "high", "Disabled identity still has an observed session", person.username, "", {"session_count": identity.session_count})
        if identity and identity.kc_enabled is False and identity.groups and person.employment_status != "active":
            add("DISABLED_RETAINS_ENTITLEMENTS", "medium", "Disabled identity still has group membership", person.username, "", {"groups": identity.groups})

    for workflow in db.scalars(select(LifecycleWorkflow).where(LifecycleWorkflow.workflow_type == "leaver", LifecycleWorkflow.status == "failed")).all():
        person = people.get(workflow.employee_number)
        add("FAILED_DEPROVISION", "critical", "Leaver workflow did not complete", person.username if person else workflow.employee_number, "", {"workflow_id": workflow.id})

    overdue = db.scalars(select(ReviewItem).join(ReviewCampaign, ReviewCampaign.id == ReviewItem.campaign_id).where(ReviewItem.status == "pending", ReviewCampaign.due_at < now)).all()
    for item in overdue:
        add("REVIEW_OVERDUE", "medium", "Access review item is overdue", item.username, item.application, {"item_id": item.id, "campaign_id": item.campaign_id})

    recent = now - timedelta(minutes=15)
    bursts = db.execute(
        select(AuditEvent.target, func.count()).where(AuditEvent.event_type == "LOGIN_ERROR", AuditEvent.occurred_at >= recent).group_by(AuditEvent.target)
    ).all()
    for target, count in bursts:
        if target and count >= 5:
            add("FAILED_AUTH_BURST", "medium", "Repeated authentication failures", target, "", {"count": count, "window_minutes": 15})

    for row in db.scalars(select(SecurityFinding)).all():
        key = (row.rule_id, row.subject or "", row.application or "")
        if key not in open_keys and row.status == "open":
            row.status = "resolved"
            row.updated_at = now
    db.flush()
    return db.scalars(select(SecurityFinding).where(SecurityFinding.status != "resolved")).all()


def evaluate_controls(db, gateway=None) -> list[ControlEvaluation]:
    seed_controls(db)
    people = db.scalars(select(HrEmployee)).all()
    identities = {row.employee_number: row for row in db.scalars(select(IdentityReference)).all()}
    from app.models import ExternalIdentityMapping

    identity_rows = []
    downstream_rows = []
    for person in people:
        identity = identities.get(person.employee_number)
        identity_rows.append({"employee_number": person.employee_number, "employment_status": person.employment_status, "kc_enabled": bool(identity.kc_enabled) if identity else False})
    for mapping in db.scalars(select(ExternalIdentityMapping)).all():
        person = db.get(HrEmployee, mapping.employee_number)
        downstream_rows.append({"employee_number": mapping.employee_number, "employment_status": person.employment_status if person else "", "downstream_active": bool(mapping.active)})
    leavers = [{"id": row.id, "status": row.status} for row in db.scalars(select(LifecycleWorkflow).where(LifecycleWorkflow.workflow_type == "leaver")).all()]
    conflicts = [{"rule_id": row.rule_id, "severity": row.severity, "status": row.status, "subject": row.subject} for row in db.scalars(select(SegregationConflict)).all()]
    grants = [{"privileged": row.privileged, "approval_id": row.access_request_id, "active": row.revoked_at is None, "role": row.role_name} for row in db.scalars(select(GrantEvidence)).all()]
    chain = verify_chain(db)
    redirects = []
    events_enabled = None
    finance_status = None
    if gateway is not None:
        try:
            redirects = gateway.client_redirects()
            events_enabled = gateway.realm_settings().get("eventsEnabled")
        except Exception as exc:
            redirects = []
            events_enabled = {"error": str(exc)[:200]}
    try:
        import httpx

        from app.config import get_settings
        response = httpx.get(get_settings().finance_reports_url, timeout=3.0, trust_env=False)
        finance_status = response.status_code
    except Exception:
        finance_status = None
    service_missing = []
    for person in people:
        if person.employment_type != "service":
            continue
        for grant in person.extra_groups or []:
            if not grant.get("approved"):
                service_missing.append({"username": person.username, "group": grant.get("group")})
    results = {
        "AC-2": account_lifecycle(identity_rows),
        "AC-2(3)": deprovisioning(leavers, downstream_rows),
        "AC-5": separation_of_duties(conflicts),
        "AC-6": least_privilege(grants),
        "AU-12": audit_generation(chain["length"] if chain["valid"] else 0, chain["valid"] if chain["length"] else None),
        "IG-CFG": configuration(redirects),
    }
    if finance_status == 401:
        results["AC-3"] = {"status": "passed", "summary": "Northstar Finance rejected an unauthenticated report request.", "evidence": [{"status_code": 401, "path": "/api/reports"}], "limitations": "One protected route was sampled. This is not a complete access-enforcement assessment."}
    elif finance_status is None:
        results["AC-3"] = {"status": "not_evaluated", "summary": "Northstar Finance could not be reached.", "evidence": [], "limitations": "The sample application was not available during evaluation."}
    else:
        results["AC-3"] = {"status": "failed", "summary": "Northstar Finance did not reject an unauthenticated request.", "evidence": [{"status_code": finance_status}], "limitations": "Only the sampled route was tested."}
    if events_enabled is True:
        results["AU-2"] = {"status": "passed", "summary": "Keycloak user events are enabled for the Northstar realm.", "evidence": [{"eventsEnabled": True}], "limitations": "This checks the realm setting, not delivery to every consumer."}
    elif events_enabled is False:
        results["AU-2"] = {"status": "failed", "summary": "Keycloak user events are disabled.", "evidence": [{"eventsEnabled": False}], "limitations": ""}
    else:
        results["AU-2"] = {"status": "not_evaluated", "summary": "Keycloak event settings were not read.", "evidence": [events_enabled] if events_enabled else [], "limitations": "The admin API observation failed."}
    if not any(person.employment_type == "service" for person in people):
        results["IG-SVC"] = {"status": "not_evaluated", "summary": "No service accounts are in the HR source.", "evidence": [], "limitations": ""}
    elif service_missing:
        results["IG-SVC"] = {"status": "failed", "summary": "A service account has access without an approval record.", "evidence": service_missing, "limitations": "Approvals are IdentityGate records, not an external ticketing system."}
    else:
        results["IG-SVC"] = {"status": "passed", "summary": "Service-account grants in the source have approval records.", "evidence": [{"service_accounts": sum(person.employment_type == "service" for person in people)}], "limitations": "Unmanaged accounts outside the source are out of scope."}
    window_end = utcnow()
    window_start = window_end - timedelta(days=30)
    stored = []
    for control_id, payload in results.items():
        row = ControlEvaluation(id=new_id(), control_id=control_id, status=payload["status"], summary=payload["summary"], evidence=payload["evidence"], limitations=payload["limitations"], evaluated_at=window_end, window_start=window_start, window_end=window_end)
        db.add(row)
        stored.append(row)
    return stored


def ingest_events(db, gateway) -> int:
    known = {row.keycloak_user_id: row.username for row in db.scalars(select(IdentityReference)).all() if row.keycloak_user_id}
    head = chain_head(db)
    prev = head or GENESIS
    added = 0
    for source, fetcher in (("keycloak-event", gateway.events), ("keycloak-admin", gateway.admin_events)):
        first = 0
        while first < 500:
            batch = fetcher(first)
            if not batch:
                break
            for event in sorted(batch, key=lambda item: item.get("time") or 0):
                reference = hashlib.sha256(json.dumps(_reference_material(source, event), sort_keys=True).encode()).hexdigest()
                if db.get(AuditEvent, reference):
                    continue
                occurred = datetime.fromtimestamp((event.get("time") or 0) / 1000, tz=timezone.utc)
                if source == "keycloak-event":
                    actor = known.get(event.get("userId"), event.get("userId"))
                    target = event.get("clientId") or known.get(event.get("userId"))
                    event_type = event.get("type") or "UNKNOWN"
                    outcome = "failed" if event.get("error") or str(event_type).endswith("ERROR") else "success"
                    metadata = redact({"ipAddress": event.get("ipAddress"), "error": event.get("error"), "details": event.get("details") or {}})
                else:
                    auth = event.get("authDetails") or {}
                    actor = known.get(auth.get("userId"), auth.get("clientId") or auth.get("userId"))
                    target = event.get("resourcePath")
                    event_type = f"ADMIN_{event.get('resourceType') or 'RESOURCE'}_{event.get('operationType') or 'UPDATE'}"
                    outcome = "success"
                    metadata = redact({"resourceType": event.get("resourceType"), "operationType": event.get("operationType")})
                payload = {"source": source, "type": event_type, "actor": actor, "target": target, "outcome": outcome, "reference": reference}
                row_hash = link(prev, payload)
                db.add(AuditEvent(id=reference, source_system=source, source_reference=reference, event_type=event_type, actor=actor, target=str(target) if target else None, outcome=outcome, correlation_id=None, occurred_at=occurred, metadata_json=metadata, prev_hash=prev, row_hash=row_hash))
                prev = row_hash
                added += 1
            if len(batch) < 100:
                break
            first += 100
    return added


def record_audit(db, *, source: str, event_type: str, actor: str | None, target: str | None, outcome: str, correlation_id: str | None, metadata: dict) -> AuditEvent:
    reference = hashlib.sha256(f"{source}|{event_type}|{actor}|{target}|{correlation_id}|{json.dumps(metadata, sort_keys=True, default=str)}".encode()).hexdigest()
    existing = db.get(AuditEvent, reference)
    if existing:
        return existing
    prev = chain_head(db) or GENESIS
    payload = {"source": source, "type": event_type, "actor": actor, "target": target, "outcome": outcome, "reference": reference}
    row = AuditEvent(id=reference, source_system=source, source_reference=reference, event_type=event_type, actor=actor, target=target, outcome=outcome, correlation_id=correlation_id, occurred_at=utcnow(), metadata_json=redact(metadata), prev_hash=prev, row_hash=link(prev, payload))
    db.add(row)
    db.flush()
    return row


def chain_head(db) -> str | None:
    rows = db.scalars(select(AuditEvent)).all()
    if not rows:
        return None
    prevs = {row.prev_hash for row in rows}
    heads = [row for row in rows if row.row_hash not in prevs]
    return heads[-1].row_hash if heads else None


def verify_chain(db) -> dict:
    from policy.audit_chain import verify

    rows = db.scalars(select(AuditEvent)).all()
    by_prev = {row.prev_hash: row for row in rows}
    ordered = []
    prev = GENESIS
    while prev in by_prev:
        row = by_prev[prev]
        ordered.append({"payload": {"source": row.source_system, "type": row.event_type, "actor": row.actor, "target": row.target, "outcome": row.outcome, "reference": row.source_reference}, "prev_hash": row.prev_hash, "row_hash": row.row_hash})
        prev = row.row_hash
    result = verify(ordered)
    result["stored"] = len(rows)
    return result


def _reference_material(source: str, event: dict) -> dict:
    if source == "keycloak-event":
        return {"source": source, "type": event.get("type"), "time": event.get("time"), "user": event.get("userId"), "session": event.get("sessionId"), "ip": event.get("ipAddress"), "error": event.get("error")}
    return {"source": source, "time": event.get("time"), "op": event.get("operationType"), "resource": event.get("resourceType"), "path": event.get("resourcePath")}

"""Access requests, certifications, expiry, and reconciliation."""

from __future__ import annotations

from datetime import timedelta

from policy.approvals import Unassignable, approval_plan, can_decide
from policy.decision import load_catalog, load_matrix
from policy.entitlements import access_paths
from policy.reviews import can_certify
from sqlalchemy import select
from sqlalchemy.orm.attributes import flag_modified

from app.keycloak.errors import IntegrationError
from app.keycloak.gateway import Gateway
from app.models import (
    AccessApproval,
    AccessRequest,
    GrantEvidence,
    HrEmployee,
    IdentityReference,
    ReconciliationItem,
    ReconciliationRun,
    RemediationTask,
    ReviewCampaign,
    ReviewDecision,
    ReviewItem,
)
from app.services.workflows import (
    _downstream_body,
    _identity,
    _remember_downstream,
    _save_observation,
    wanted_groups,
    wanted_roles,
)
from app.util import new_id, utcnow

SKIP_ROLES = {"employee", "identitygate-user"}


def _group_for(application: str, role: str) -> str | None:
    matches = []
    for name, binding in load_catalog()["groups"].items():
        roles = (binding.get("clients") or {}).get(application) or []
        if roles == [role] and not binding.get("realm"):
            matches.append(name)
    preferred = [name for name in matches if not name.startswith(("dept-", "service-"))]
    return (preferred or matches or [None])[0]


def create_request(db, requester: str, target: str, application: str, role: str, justification: str, duration_hours: int, correlation_id: str) -> AccessRequest:
    matrix = load_matrix()
    catalog = load_catalog()
    if application not in matrix["applications"] and application != "realm":
        raise IntegrationError("Unknown application.", retryable=False, status=400)
    if len(justification.strip()) < 8:
        raise IntegrationError("A business justification is required.", retryable=False, status=400)
    if duration_hours < 1 or duration_hours > 24 * 90:
        raise IntegrationError("Duration must be between 1 hour and 90 days.", retryable=False, status=400)
    person = db.scalar(select(HrEmployee).where(HrEmployee.username == target))
    if person is None:
        raise IntegrationError("Target identity was not found.", retryable=False, status=404)
    try:
        steps = approval_plan(
            target=target,
            requester=requester,
            manager=person.manager_username,
            role=role,
            privileged_roles=set(matrix["privileged_roles"]),
            security_reviewer=catalog["security_reviewer"],
            independent_reviewer="helen.cho",
        )
    except Unassignable as exc:
        raise IntegrationError(str(exc), retryable=False, status=409) from exc
    row = AccessRequest(
        id=new_id(),
        requester=requester,
        target=target,
        application=application,
        role_name=role,
        justification=justification.strip(),
        duration_hours=duration_hours,
        status="awaiting_approval",
        steps=steps,
        correlation_id=correlation_id,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db.add(row)
    db.flush()
    return row


def decide_request(db, gateway: Gateway, request_id: str, actor: str, approve: bool, reason: str) -> AccessRequest:
    row = db.get(AccessRequest, request_id)
    if row is None:
        raise IntegrationError("Request was not found.", retryable=False, status=404)
    if row.status != "awaiting_approval":
        raise IntegrationError("Request is not awaiting approval.", retryable=False, status=409)
    allowed, kind = can_decide(row.steps, actor, row.target, row.requester)
    if not allowed:
        raise IntegrationError(kind, retryable=False, status=403)
    if len(reason.strip()) < 3:
        raise IntegrationError("A decision reason is required.", retryable=False, status=400)
    for step in row.steps:
        if step["status"] == "pending" and step["username"] == actor:
            step["status"] = "approved" if approve else "denied"
            break
    row.updated_at = utcnow()
    flag_modified(row, "steps")
    db.add(AccessApproval(id=new_id(), request_id=row.id, step_kind=kind, approver=actor, decision="approved" if approve else "denied", reason=reason.strip(), decided_at=utcnow()))
    if not approve:
        row.status = "denied"
        return row
    if any(step["status"] == "pending" for step in row.steps):
        return row
    row.status = "provisioning"
    db.flush()
    try:
        _fulfil(db, gateway, row)
    except IntegrationError:
        row.status = "failed"
        db.commit()
        raise
    return row


def _fulfil(db, gateway: Gateway, row: AccessRequest) -> None:
    person = db.scalar(select(HrEmployee).where(HrEmployee.username == row.target))
    identity = db.scalar(select(IdentityReference).where(IdentityReference.username == row.target))
    if person is None or identity is None or not identity.keycloak_user_id:
        raise IntegrationError("Target account is not provisioned.", retryable=False)
    group = _group_for(row.application, row.role_name) if row.application != "realm" else None
    if group:
        extras = list(person.extra_groups or [])
        if not any(item["group"] == group for item in extras):
            extras.append({"group": group, "approved": True, "approver": row.steps[-1]["username"], "justification": row.justification, "approval_id": row.id})
        person.extra_groups = extras
        person.suppressed_groups = [item for item in (person.suppressed_groups or []) if item != group]
        gateway.sync_groups(identity.keycloak_user_id, wanted_groups(person), db, row.correlation_id, person.employee_number)
    else:
        directs = list(person.direct_roles or [])
        if not any(item["client"] == row.application and item["role"] == row.role_name for item in directs):
            directs.append({"client": row.application, "role": row.role_name, "approved": True, "expires_at": (utcnow() + timedelta(hours=row.duration_hours)).isoformat()})
        person.direct_roles = directs
        person.suppressed_roles = [item for item in (person.suppressed_roles or []) if item != f"{row.application}:{row.role_name}"]
        gateway.sync_direct_roles(identity.keycloak_user_id, wanted_roles(person))
        group = None
    observed = gateway.observe(identity.keycloak_user_id)
    effective = set(observed["effective_client_roles"].get(row.application, []))
    if row.application == "realm":
        effective = set(observed["effective_realm_roles"])
    if row.role_name not in effective:
        raise IntegrationError("The target system did not confirm the role assignment.", retryable=True)
    _save_observation(identity, observed, observed["enabled"], True, "joiner")
    expires = utcnow() + timedelta(hours=row.duration_hours)
    grant = GrantEvidence(
        id=new_id(),
        employee_number=person.employee_number,
        source="approval",
        application=row.application,
        role_name=row.role_name,
        group_name=group,
        access_request_id=row.id,
        privileged=row.role_name in set(load_matrix()["privileged_roles"]),
        granted_at=utcnow(),
        expires_at=expires,
        correlation_id=row.correlation_id,
    )
    db.add(grant)
    row.grant_id = grant.id
    row.status = "fulfilled"
    downstream = gateway.downstream_upsert(_downstream_body(person, wanted_groups(person), wanted_roles(person), person.employment_status == "active"), db, row.correlation_id)
    _remember_downstream(db, person.employee_number, downstream)


def create_campaign(db, *, name: str, kind: str, reviewer: str, due_at, scope: dict, actor: str) -> ReviewCampaign:
    catalog = load_catalog()
    matrix = load_matrix()
    campaign = ReviewCampaign(
        id=new_id(),
        name=name,
        kind=kind,
        scope=scope,
        reviewer=reviewer,
        due_at=due_at,
        status="active",
        policy_version=matrix["version"],
        created_at=utcnow(),
    )
    db.add(campaign)
    db.flush()
    people = db.scalars(select(HrEmployee)).all()
    identities = {row.employee_number: row for row in db.scalars(select(IdentityReference)).all()}
    for person in people:
        if kind == "department" and person.department != scope.get("department"):
            continue
        if kind == "contractor" and person.employment_type != "contractor":
            continue
        identity = identities.get(person.employee_number)
        if identity is None:
            continue
        paths = access_paths(
            identity.groups or [],
            identity.direct_client_roles or {},
            identity.direct_realm_roles or [],
            identity.effective_client_roles or {},
            identity.effective_realm_roles or [],
            catalog,
            matrix,
        )
        seen = set()
        for path in paths:
            if path["role"] in SKIP_ROLES or not path["role"]:
                continue
            if kind == "application" and path["application"] != scope.get("application"):
                continue
            if kind == "privileged" and not path["privileged"]:
                continue
            key = (path["application"], path["role"])
            if key in seen:
                continue
            seen.add(key)
            assigned = reviewer if reviewer != person.username else catalog["security_reviewer"]
            if assigned == person.username:
                assigned = "helen.cho"
            db.add(
                ReviewItem(
                    id=new_id(),
                    campaign_id=campaign.id,
                    employee_number=person.employee_number,
                    username=person.username,
                    application=path["application"],
                    role_name=path["role"],
                    grant_source=path["source"] if path["source"] in {"group", "direct"} else "unresolved",
                    grant_group=path.get("group"),
                    privileged=path["privileged"],
                    reviewer=assigned,
                    status="pending",
                    remediation_status="not_required",
                    snapshot={
                        "observed_at": identity.observed_at.isoformat() if identity.observed_at else None,
                        "source": path["source"],
                        "group": path.get("group"),
                        "actor": actor,
                    },
                    created_at=utcnow(),
                )
            )
    return campaign


def decide_item(db, gateway: Gateway, item_id: str, actor: str, decision: str, reason: str) -> ReviewItem:
    item = db.get(ReviewItem, item_id)
    if item is None:
        raise IntegrationError("Review item was not found.", retryable=False, status=404)
    if item.status not in {"pending", "clarification"}:
        raise IntegrationError("This item already has a final decision.", retryable=False, status=409)
    allowed, message = can_certify(actor, item.username)
    if not allowed:
        raise IntegrationError(message, retryable=False, status=403)
    if actor != item.reviewer:
        raise IntegrationError("This item is assigned to a different reviewer.", retryable=False, status=403)
    if decision not in {"approve", "revoke", "clarification"}:
        raise IntegrationError("Unsupported decision.", retryable=False, status=400)
    if len(reason.strip()) < 8:
        raise IntegrationError("A justification is required.", retryable=False, status=400)
    db.add(ReviewDecision(id=new_id(), item_id=item.id, campaign_id=item.campaign_id, reviewer=actor, decision=decision, reason=reason.strip(), decided_at=utcnow()))
    if decision == "clarification":
        item.status = "clarification"
        return item
    if decision == "approve":
        item.status = "approved"
        item.remediation_status = "not_required"
        return item
    item.status = "revoked"
    item.remediation_status = "pending_removal"
    task = RemediationTask(id=new_id(), source_type="review_item", source_id=item.id, employee_number=item.employee_number, action="remove-entitlement", status="pending", detail={}, created_at=utcnow(), updated_at=utcnow())
    db.add(task)
    db.flush()
    _remove_entitlement(db, gateway, item, task)
    return item


def _remove_entitlement(db, gateway: Gateway, item: ReviewItem, task: RemediationTask) -> None:
    person = db.get(HrEmployee, item.employee_number)
    identity = db.scalar(select(IdentityReference).where(IdentityReference.employee_number == item.employee_number))
    if person is None or identity is None or not identity.keycloak_user_id:
        item.remediation_status = "removal_failed"
        task.status = "failed"
        task.detail = {"error": "Identity is not linked to Keycloak."}
        return
    if item.grant_source == "group" and item.grant_group:
        person.suppressed_groups = sorted(set(person.suppressed_groups or []) | {item.grant_group})
        person.extra_groups = [entry for entry in (person.extra_groups or []) if entry.get("group") != item.grant_group]
        gateway.sync_groups(identity.keycloak_user_id, wanted_groups(person), db, item.id, person.employee_number)
    elif item.grant_source == "direct":
        key = f"{item.application}:{item.role_name}"
        person.suppressed_roles = sorted(set(person.suppressed_roles or []) | {key})
        person.direct_roles = [entry for entry in (person.direct_roles or []) if not (entry.get("client") == item.application and entry.get("role") == item.role_name)]
        gateway.sync_direct_roles(identity.keycloak_user_id, wanted_roles(person))
    else:
        item.remediation_status = "removal_failed"
        task.status = "failed"
        task.detail = {"error": "The grant path is unresolved, so it was not changed automatically."}
        return
    observed = gateway.observe(identity.keycloak_user_id)
    _save_observation(identity, observed, observed["enabled"], True, "joiner")
    effective = observed["effective_realm_roles"] if item.application == "realm" else observed["effective_client_roles"].get(item.application, [])
    if item.role_name in effective:
        item.remediation_status = "reconciliation_pending"
        task.status = "reconciliation_pending"
        task.detail = {"remaining": True}
        return
    now = utcnow()
    grants = db.scalars(
        select(GrantEvidence).where(
            GrantEvidence.employee_number == person.employee_number,
            GrantEvidence.application == item.application,
            GrantEvidence.role_name == item.role_name,
            GrantEvidence.revoked_at.is_(None),
        )
    ).all()
    for grant in grants:
        if item.grant_group and grant.group_name not in {item.grant_group, None}:
            continue
        grant.revoked_at = now
    item.remediation_status = "removal_succeeded"
    task.status = "succeeded"
    task.detail = {"removed": True}
    task.updated_at = now
    downstream = gateway.downstream_upsert(_downstream_body(person, wanted_groups(person), wanted_roles(person), person.employment_status == "active"), db, item.id)
    _remember_downstream(db, person.employee_number, downstream)


def reassign_item(db, item_id: str, reviewer: str, actor: str) -> ReviewItem:
    item = db.get(ReviewItem, item_id)
    if item is None:
        raise IntegrationError("Review item was not found.", retryable=False, status=404)
    if reviewer == item.username:
        raise IntegrationError("The subject cannot be assigned their own review.", retryable=False, status=403)
    item.reviewer = reviewer
    item.snapshot = {**(item.snapshot or {}), "reassigned_by": actor, "reassigned_at": utcnow().isoformat()}
    return item


def expire_due(db, gateway: Gateway) -> list[str]:
    now = utcnow()
    grants = db.scalars(select(GrantEvidence).where(GrantEvidence.expires_at.is_not(None), GrantEvidence.expires_at <= now, GrantEvidence.revoked_at.is_(None))).all()
    changed = []
    for grant in grants:
        person = db.get(HrEmployee, grant.employee_number)
        identity = _identity(db, person) if person else None
        if person is None or identity is None or not identity.keycloak_user_id:
            continue
        if grant.group_name:
            person.suppressed_groups = sorted(set(person.suppressed_groups or []) | {grant.group_name})
            person.extra_groups = [entry for entry in (person.extra_groups or []) if entry.get("group") != grant.group_name]
            gateway.sync_groups(identity.keycloak_user_id, wanted_groups(person), db, grant.id, person.employee_number)
        else:
            key = f"{grant.application}:{grant.role_name}"
            person.suppressed_roles = sorted(set(person.suppressed_roles or []) | {key})
            person.direct_roles = [entry for entry in (person.direct_roles or []) if not (entry.get("client") == grant.application and entry.get("role") == grant.role_name)]
            gateway.sync_direct_roles(identity.keycloak_user_id, wanted_roles(person))
        observed = gateway.observe(identity.keycloak_user_id)
        effective = observed["effective_realm_roles"] if grant.application == "realm" else observed["effective_client_roles"].get(grant.application, [])
        if grant.role_name in effective:
            if grant.access_request_id:
                request = db.get(AccessRequest, grant.access_request_id)
                if request:
                    request.status = "failed"
            continue
        grant.revoked_at = now
        if grant.access_request_id:
            request = db.get(AccessRequest, grant.access_request_id)
            if request and request.status == "fulfilled":
                request.status = "expired"
        changed.append(grant.id)
        downstream = gateway.downstream_upsert(_downstream_body(person, wanted_groups(person), wanted_roles(person), person.employment_status == "active"), db, grant.id)
        _remember_downstream(db, person.employee_number, downstream)
    return changed


def reconcile(db, gateway: Gateway) -> ReconciliationRun:
    actual_rows = gateway.downstream_list()
    actual = {row.get("externalId"): row for row in actual_rows if row.get("externalId")}
    people = db.scalars(select(HrEmployee)).all()
    run = ReconciliationRun(id=new_id(), system="northstar-directory", status="completed", desired_count=len(people), actual_count=len(actual), summary={}, created_at=utcnow())
    db.add(run)
    db.flush()
    counts = {"missing": 0, "extra": 0, "status": 0, "groups": 0, "roles": 0}
    seen = set()
    for person in people:
        groups = wanted_groups(person) if person.employment_status == "active" else []
        roles = wanted_roles(person) if person.employment_status == "active" else []
        desired = _downstream_body(person, groups, roles, person.employment_status == "active")
        seen.add(person.employee_number)
        current = actual.get(person.employee_number)
        if current is None:
            counts["missing"] += 1
            _item(db, run.id, person.employee_number, "missing", desired, None)
            continue
        if bool(current.get("active")) != desired["active"]:
            counts["status"] += 1
            _item(db, run.id, person.employee_number, "status", desired, {"active": current.get("active")})
        actual_groups = sorted(current.get("groups") or [])
        if actual_groups != sorted(desired["groups"]):
            counts["groups"] += 1
            _item(db, run.id, person.employee_number, "groups", {"groups": desired["groups"]}, {"groups": actual_groups})
        extension = current.get("urn:northstar:params:scim:schemas:extension:access:1.0:User") or {}
        actual_roles = sorted(extension.get("roles") or [])
        if actual_roles != sorted(desired["roles"]):
            counts["roles"] += 1
            _item(db, run.id, person.employee_number, "roles", {"roles": desired["roles"]}, {"roles": actual_roles})
    for external_id, current in actual.items():
        if external_id not in seen:
            counts["extra"] += 1
            _item(db, run.id, external_id, "extra", {"active": False}, {"userName": current.get("userName"), "active": current.get("active")})
    run.summary = counts
    return run


def _item(db, run_id: str, external_id: str, kind: str, desired, actual) -> None:
    db.add(ReconciliationItem(id=new_id(), run_id=run_id, external_id=external_id, kind=kind, desired=desired, actual=actual, status="open"))


def repair(db, gateway: Gateway, run_id: str, item_ids: list[str]) -> dict:
    items = db.scalars(select(ReconciliationItem).where(ReconciliationItem.run_id == run_id, ReconciliationItem.id.in_(item_ids))).all()
    done = []
    for item in items:
        person = db.get(HrEmployee, item.external_id)
        if item.kind == "extra":
            if person is None:
                item.status = "skipped"
                continue
        if person is None:
            item.status = "skipped"
            continue
        active = person.employment_status == "active" and item.kind != "extra"
        result = gateway.downstream_upsert(
            _downstream_body(person, wanted_groups(person) if active else [], wanted_roles(person) if active else [], active),
            db,
            run_id,
        )
        _remember_downstream(db, person.employee_number, result)
        item.status = "repaired"
        done.append(item.id)
    return {"repaired": done}

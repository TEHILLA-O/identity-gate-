"""Joiner, mover, and leaver workflows.

A workflow is succeeded only after the verification stage observes the expected state.
A failed downstream call leaves the workflow failed.
"""

from __future__ import annotations

from datetime import datetime, timezone

from policy.decision import load_catalog, load_matrix
from policy.entitlements import desired_groups, diff_assignments, groups_after_move, roles_from_groups
from sqlalchemy import select
from sqlalchemy.orm.attributes import flag_modified

from app.keycloak.errors import IntegrationError
from app.keycloak.gateway import Gateway
from app.models import (
    AccessApproval,
    AccessRequest,
    EntitlementSnapshot,
    ExternalIdentityMapping,
    GrantEvidence,
    HrEmployee,
    IdentityReference,
    LifecycleWorkflow,
)
from app.util import iso, new_id, utcnow

COST = {
    "Engineering": "ENG-200",
    "Finance": "FIN-310",
    "Sales": "SAL-420",
    "Human Resources": "HR-150",
    "Operations": "OPS-600",
    "Security": "SEC-100",
}

JOINER = [
    ("validate", "IdentityGate"),
    ("keycloak", "Keycloak SCIM"),
    ("assignments", "Keycloak"),
    ("downstream", "Northstar Directory"),
    ("onboarding", "Keycloak"),
    ("verify", "IdentityGate"),
]
MOVER = [
    ("detect", "HR"),
    ("diff", "IdentityGate"),
    ("approval_gate", "IdentityGate"),
    ("apply", "Keycloak"),
    ("downstream", "Northstar Directory"),
    ("verify", "IdentityGate"),
]
LEAVER = [
    ("detect", "HR"),
    ("disable", "Keycloak SCIM"),
    ("sessions", "Keycloak"),
    ("entitlements", "Keycloak"),
    ("downstream", "Northstar Directory"),
    ("verify", "IdentityGate"),
]


def employee_dict(row: HrEmployee) -> dict:
    return {
        "employee_number": row.employee_number,
        "username": row.username,
        "given_name": row.given_name,
        "family_name": row.family_name,
        "email": row.email,
        "department": row.department,
        "title": row.title,
        "manager_username": row.manager_username,
        "employment_status": row.employment_status,
        "employment_type": row.employment_type,
        "join_date": row.join_date,
        "departure_date": row.departure_date,
        "cost_centre": row.cost_centre,
        "classification": row.classification,
        "access_expires_at": row.access_expires_at,
        "extra_groups": row.extra_groups or [],
        "direct_roles": row.direct_roles or [],
    }


def wanted_groups(row: HrEmployee) -> list[str]:
    suppressed = set(row.suppressed_groups or [])
    return [group for group in desired_groups(employee_dict(row)) if group not in suppressed]


def wanted_roles(row: HrEmployee) -> list[dict]:
    suppressed = set(row.suppressed_roles or [])
    return [role for role in (row.direct_roles or []) if f"{role['client']}:{role['role']}" not in suppressed and not _expired(role.get("expires_at"))]


def _expired(value: str | None) -> bool:
    if not value:
        return False
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed <= datetime.now(timezone.utc)


def _stages(spec: list[tuple[str, str]]) -> list[dict]:
    return [
        {"key": key, "system": system, "status": "pending", "started_at": None, "finished_at": None, "error": None, "retryable": False, "result": None}
        for key, system in spec
    ]


def _workflow(db, workflow_id: str | None, kind: str, employee_number: str, spec, correlation_id: str) -> LifecycleWorkflow:
    if workflow_id:
        row = db.get(LifecycleWorkflow, workflow_id)
        if row is None:
            raise IntegrationError("Workflow was not found.", retryable=False, status=404)
        return row
    row = LifecycleWorkflow(
        id=new_id(),
        workflow_type=kind,
        employee_number=employee_number,
        status="running",
        correlation_id=correlation_id,
        stages=_stages(spec),
        diff=None,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db.add(row)
    db.flush()
    return row


def _run(db, workflow: LifecycleWorkflow, steps: list[tuple[str, object]]) -> LifecycleWorkflow:
    for key, fn in steps:
        stage = next(item for item in workflow.stages if item["key"] == key)
        if stage["status"] == "succeeded":
            continue
        stage["status"] = "running"
        stage["started_at"] = iso(utcnow())
        stage["error"] = None
        workflow.status = "running"
        workflow.updated_at = utcnow()
        flag_modified(workflow, "stages")
        db.commit()
        try:
            result = fn()
        except IntegrationError as exc:
            _fail(db, workflow, stage, str(exc), exc.retryable)
            exc.workflow_id = workflow.id  # type: ignore[attr-defined]
            raise
        except Exception as exc:
            _fail(db, workflow, stage, str(exc)[:400], True)
            error = IntegrationError(str(exc)[:400], retryable=True)
            error.workflow_id = workflow.id  # type: ignore[attr-defined]
            raise error from exc
        stage["status"] = "succeeded"
        stage["finished_at"] = iso(utcnow())
        stage["result"] = result
        flag_modified(workflow, "stages")
        workflow.updated_at = utcnow()
        db.commit()
    workflow.status = "succeeded"
    workflow.updated_at = utcnow()
    db.commit()
    return workflow


def _fail(db, workflow, stage, message: str, retryable: bool) -> None:
    stage["status"] = "failed"
    stage["finished_at"] = iso(utcnow())
    stage["error"] = message
    stage["retryable"] = retryable
    stage["attempts"] = int(stage.get("attempts") or 0) + 1
    workflow.status = "failed"
    workflow.updated_at = utcnow()
    flag_modified(workflow, "stages")
    db.commit()


def _identity(db, row: HrEmployee) -> IdentityReference:
    identity = db.scalar(select(IdentityReference).where(IdentityReference.employee_number == row.employee_number))
    if identity is None:
        identity = IdentityReference(
            id=new_id(),
            employee_number=row.employee_number,
            username=row.username,
            account_state="pending_provisioning",
            source="northstar-hr",
            groups=[],
            direct_client_roles={},
            direct_realm_roles=[],
            effective_client_roles={},
            effective_realm_roles=[],
        )
        db.add(identity)
        db.flush()
    return identity


def _save_observation(identity: IdentityReference, observed: dict, enabled: bool, success: bool, kind: str) -> None:
    identity.keycloak_user_id = identity.keycloak_user_id
    identity.kc_enabled = observed["enabled"]
    identity.groups = observed["groups"]
    identity.direct_client_roles = observed["direct_client_roles"]
    identity.direct_realm_roles = observed["direct_realm_roles"]
    identity.effective_client_roles = observed["effective_client_roles"]
    identity.effective_realm_roles = observed["effective_realm_roles"]
    identity.mfa_enrolled = observed["mfa_enrolled"]
    identity.session_count = observed["session_count"]
    identity.observed_at = utcnow()
    if not success and kind == "leaver":
        identity.account_state = "pending_deprovisioning"
    elif not success:
        identity.account_state = "provisioning_failed"
    elif enabled:
        identity.account_state = "active"
    else:
        identity.account_state = "disabled"


def _manager(db, row: HrEmployee) -> tuple[str | None, str | None]:
    if not row.manager_username:
        return None, None
    manager = db.scalar(select(IdentityReference).where(IdentityReference.username == row.manager_username))
    hr = db.scalar(select(HrEmployee).where(HrEmployee.username == row.manager_username))
    if manager is None or not manager.keycloak_user_id or hr is None:
        return None, None
    return manager.keycloak_user_id, f"{hr.given_name} {hr.family_name}"


def _downstream_body(row: HrEmployee, groups: list[str], roles: list[dict], active: bool) -> dict:
    catalog = load_catalog()
    held = roles_from_groups(groups, catalog)
    for role in roles:
        held.setdefault(role["client"], set()).add(role["role"])
    flat = [f"{app}:{role}" for app, names in sorted(held.items()) if app != "realm" for role in sorted(names)]
    return {
        "externalId": row.employee_number,
        "userName": row.username,
        "active": active,
        "name": {"givenName": row.given_name, "familyName": row.family_name},
        "emails": [{"value": row.email, "type": "work", "primary": True}],
        "title": row.title,
        "department": row.department,
        "groups": groups,
        "roles": flat,
    }


def _remember_downstream(db, employee_number: str, result: dict) -> None:
    mapping = db.scalar(
        select(ExternalIdentityMapping).where(
            ExternalIdentityMapping.system == "northstar-directory",
            ExternalIdentityMapping.external_id == employee_number,
        )
    )
    if mapping is None:
        mapping = ExternalIdentityMapping(
            id=new_id(),
            employee_number=employee_number,
            system="northstar-directory",
            external_id=employee_number,
        )
        db.add(mapping)
    mapping.resource_id = result.get("id")
    mapping.active = result.get("active")
    mapping.observed_at = utcnow()


def _validate(row: HrEmployee, db) -> dict:
    catalog = load_catalog()
    if row.department not in catalog["department_groups"]:
        raise IntegrationError(f"{row.department} is not a known department.", retryable=False)
    if not row.email.endswith("@northstar.example"):
        raise IntegrationError("Identity source email must use the northstar.example domain.", retryable=False)
    if row.manager_username:
        manager = db.get(HrEmployee, db.scalar(select(HrEmployee.employee_number).where(HrEmployee.username == row.manager_username)) or "")
        if manager is None:
            raise IntegrationError("Manager was not found in the HR source.", retryable=False)
    return {"employee_number": row.employee_number, "department": row.department}


def _record_grants(db, row: HrEmployee, correlation_id: str) -> None:
    matrix = load_matrix()
    catalog = load_catalog()
    privileged = set(matrix["privileged_roles"])
    groups = wanted_groups(row)
    for group in groups:
        binding = catalog["groups"].get(group) or {"realm": [], "clients": {}}
        targets = [("realm", role) for role in binding.get("realm") or []]
        for app, roles in (binding.get("clients") or {}).items():
            targets.extend((app, role) for role in roles)
        source = "birthright" if group in {catalog["department_groups"].get(row.department), *catalog["birthright_groups"], "contractors", "service-accounts"} else "assignment"
        extra = next((item for item in (row.extra_groups or []) if item["group"] == group), None)
        for application, role in targets:
            _ensure_grant(db, row, source, application, role, group, role in privileged, extra, correlation_id)
    for role in wanted_roles(row):
        _ensure_grant(db, row, "direct", role["client"], role["role"], None, role["role"] in privileged, role, correlation_id)


def _ensure_grant(db, row, source, application, role, group, privileged, approval_meta, correlation_id: str) -> None:
    existing = db.scalar(
        select(GrantEvidence).where(
            GrantEvidence.employee_number == row.employee_number,
            GrantEvidence.application == application,
            GrantEvidence.role_name == role,
            GrantEvidence.group_name == group,
            GrantEvidence.revoked_at.is_(None),
        )
    )
    if existing:
        return
    request_id = None
    if approval_meta and approval_meta.get("approved") and approval_meta.get("approver"):
        request_id = new_id()
        db.add(
            AccessRequest(
                id=request_id,
                requester="northstar-hr",
                target=row.username,
                application=application,
                role_name=role,
                justification=approval_meta.get("justification") or "Approved before provisioning.",
                duration_hours=0,
                status="fulfilled",
                steps=[{"kind": "recorded", "username": approval_meta["approver"], "status": "approved"}],
                correlation_id=correlation_id,
                created_at=utcnow(),
                updated_at=utcnow(),
            )
        )
        db.flush()
        db.add(
            AccessApproval(
                id=new_id(),
                request_id=request_id,
                step_kind="recorded",
                approver=approval_meta["approver"],
                decision="approved",
                reason=approval_meta.get("justification") or "",
                decided_at=utcnow(),
            )
        )
    db.add(
        GrantEvidence(
            id=new_id(),
            employee_number=row.employee_number,
            source=source,
            application=application,
            role_name=role,
            group_name=group,
            access_request_id=request_id,
            privileged=privileged,
            granted_at=utcnow(),
            expires_at=_parse_dt(approval_meta.get("expires_at")) if approval_meta else None,
            correlation_id=correlation_id,
        )
    )


def _parse_dt(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def run_joiner(db, gateway: Gateway, employee_number: str, *, correlation_id: str, workflow_id: str | None = None, active: bool | None = None, onboarding: bool = False, password: str = "") -> LifecycleWorkflow:
    row = db.get(HrEmployee, employee_number)
    if row is None:
        raise IntegrationError("HR record was not found.", retryable=False, status=404)
    identity = _identity(db, row)
    enabled = row.employment_status == "active" if active is None else active
    workflow = _workflow(db, workflow_id, "joiner", employee_number, JOINER, correlation_id)
    holder: dict = {}

    def validate():
        return _validate(row, db)

    def provision():
        manager_id, manager_name = _manager(db, row)
        user_id = gateway.upsert_user(row and employee_dict(row), manager_id=manager_id, manager_name=manager_name, active=enabled, db=db, correlation_id=correlation_id)
        identity.keycloak_user_id = user_id
        db.flush()
        if password and row.employment_type in {"employee", "contractor"}:
            gateway.set_password(user_id, password, db, correlation_id)
        holder["user_id"] = user_id
        return {"keycloak_user_id": user_id, "active": enabled}

    def assignments():
        user_id = identity.keycloak_user_id or holder["user_id"]
        groups = wanted_groups(row)
        roles = wanted_roles(row)
        gateway.sync_groups(user_id, groups, db, correlation_id, row.employee_number)
        gateway.sync_direct_roles(user_id, roles)
        _record_grants(db, row, correlation_id)
        return {"groups": groups, "direct_roles": roles}

    def downstream():
        result = gateway.downstream_upsert(_downstream_body(row, wanted_groups(row), wanted_roles(row), enabled), db, correlation_id)
        _remember_downstream(db, row.employee_number, result)
        return result

    def onboarding_actions():
        if not onboarding:
            return {"required_actions": [], "note": "Seeded identity. Required actions were not applied."}
        actions = ["CONFIGURE_TOTP"] if row.classification == "privileged" else ["VERIFY_EMAIL"]
        gateway.set_required_actions(identity.keycloak_user_id, actions)
        return {"required_actions": actions}

    def verify():
        observed = gateway.observe(identity.keycloak_user_id)
        if observed["enabled"] != enabled:
            raise IntegrationError("Keycloak account state does not match the requested state.", retryable=True)
        missing = sorted(set(wanted_groups(row)) - set(observed["groups"]))
        if missing:
            raise IntegrationError(f"Group assignment did not converge: {', '.join(missing)}", retryable=True)
        _save_observation(identity, observed, enabled, True, "joiner")
        return {"enabled": observed["enabled"], "groups": observed["groups"]}

    try:
        return _run(db, workflow, [("validate", validate), ("keycloak", provision), ("assignments", assignments), ("downstream", downstream), ("onboarding", onboarding_actions), ("verify", verify)])
    except IntegrationError:
        if identity.keycloak_user_id:
            try:
                _save_observation(identity, gateway.observe(identity.keycloak_user_id), enabled, False, "joiner")
                db.commit()
            except Exception:
                pass
        raise


def run_mover(db, gateway: Gateway, employee_number: str, new_department: str, *, correlation_id: str, workflow_id: str | None = None) -> LifecycleWorkflow:
    row = db.get(HrEmployee, employee_number)
    if row is None:
        raise IntegrationError("HR record was not found.", retryable=False, status=404)
    catalog = load_catalog()
    matrix = load_matrix()
    if new_department not in catalog["department_groups"]:
        raise IntegrationError("Unknown department.", retryable=False)
    identity = _identity(db, row)
    workflow = _workflow(db, workflow_id, "mover", employee_number, MOVER, correlation_id)
    before_groups = list(identity.groups or wanted_groups(row))
    before_direct = {client: list(roles) for client, roles in (identity.direct_client_roles or {}).items()}

    def detect():
        if row.department == new_department and row.employment_status == "active":
            raise IntegrationError("Department has not changed.", retryable=False)
        return {"from": row.department, "to": new_department}

    def diff():
        after = groups_after_move(employee_dict(row), new_department, catalog)
        after = [group for group in after if group not in set(row.suppressed_groups or [])]
        compared = diff_assignments(before_groups, after, before_direct, {}, catalog)
        privileged = [item for item in compared["added"] if item["role"] in set(matrix["privileged_roles"])]
        workflow.diff = {"before_groups": before_groups, "after_groups": after, **compared, "privileged_additions": privileged}
        flag_modified(workflow, "diff")
        db.add(EntitlementSnapshot(id=new_id(), employee_number=row.employee_number, reason="mover-before", payload={"groups": before_groups, "direct": before_direct}, created_at=utcnow()))
        return compared

    def approval_gate():
        privileged = (workflow.diff or {}).get("privileged_additions") or []
        if privileged:
            raise IntegrationError("This move would add privileged access. Submit an access request instead.", retryable=False)
        return {"approval": "not_required", "reason": "Only birthright access changed. Previous application extras are removed."}

    def apply():
        row.department = new_department
        row.cost_centre = COST[new_department]
        row.direct_roles = []
        row.extra_groups = [item for item in (row.extra_groups or []) if item["group"].startswith("identity-")]
        row.updated_at = utcnow()
        manager_id, manager_name = _manager(db, row)
        gateway.upsert_user(employee_dict(row), manager_id=manager_id, manager_name=manager_name, active=True, db=db, correlation_id=correlation_id)
        gateway.sync_groups(identity.keycloak_user_id, wanted_groups(row), db, correlation_id, row.employee_number)
        gateway.sync_direct_roles(identity.keycloak_user_id, [])
        return {"groups": wanted_groups(row)}

    def downstream():
        result = gateway.downstream_upsert(_downstream_body(row, wanted_groups(row), [], True), db, correlation_id)
        _remember_downstream(db, row.employee_number, result)
        return result

    def verify():
        observed = gateway.observe(identity.keycloak_user_id)
        missing = sorted(set(wanted_groups(row)) - set(observed["groups"]))
        extra = sorted(set(observed["groups"]) - set(wanted_groups(row)))
        if missing or extra:
            raise IntegrationError(f"Group state did not converge. missing={missing} extra={extra}", retryable=True)
        _save_observation(identity, observed, True, True, "mover")
        db.add(EntitlementSnapshot(id=new_id(), employee_number=row.employee_number, reason="mover-after", payload={"groups": observed["groups"], "direct": observed["direct_client_roles"]}, created_at=utcnow()))
        return {"groups": observed["groups"]}

    return _run(db, workflow, [("detect", detect), ("diff", diff), ("approval_gate", approval_gate), ("apply", apply), ("downstream", downstream), ("verify", verify)])


def run_leaver(db, gateway: Gateway, employee_number: str, *, correlation_id: str, workflow_id: str | None = None) -> LifecycleWorkflow:
    row = db.get(HrEmployee, employee_number)
    if row is None:
        raise IntegrationError("HR record was not found.", retryable=False, status=404)
    identity = _identity(db, row)
    workflow = _workflow(db, workflow_id, "leaver", employee_number, LEAVER, correlation_id)

    def detect():
        return {"employment_status": row.employment_status, "username": row.username}

    def disable():
        row.employment_status = "departed"
        row.classification = "departed"
        if not row.departure_date:
            row.departure_date = utcnow().date().isoformat()
        row.updated_at = utcnow()
        manager_id, manager_name = _manager(db, row)
        if not identity.keycloak_user_id:
            raise IntegrationError("No Keycloak account is linked, so disablement cannot be verified.", retryable=False)
        gateway.upsert_user(employee_dict(row), manager_id=manager_id, manager_name=manager_name, active=False, db=db, correlation_id=correlation_id)
        return {"requested_active": False}

    def sessions():
        gateway.logout(identity.keycloak_user_id)
        observed = gateway.observe(identity.keycloak_user_id)
        return {
            "session_count": observed["session_count"],
            "limitation": "Keycloak sessions were revoked. Access tokens already issued remain valid until they expire (300 seconds) unless an application refreshes or repeats a token check. Downstream accounts are disabled separately.",
        }

    def entitlements():
        gateway.sync_groups(identity.keycloak_user_id, [], db, correlation_id, row.employee_number)
        gateway.sync_direct_roles(identity.keycloak_user_id, [])
        now = utcnow()
        grants = db.scalars(select(GrantEvidence).where(GrantEvidence.employee_number == row.employee_number, GrantEvidence.revoked_at.is_(None))).all()
        for grant in grants:
            grant.revoked_at = now
        return {"removed_grants": len(grants)}

    def downstream():
        result = gateway.downstream_upsert(_downstream_body(row, [], [], False), db, correlation_id)
        _remember_downstream(db, row.employee_number, result)
        if result.get("active") is not False:
            raise IntegrationError("Downstream account is still active.", retryable=True)
        return result

    def verify():
        observed = gateway.observe(identity.keycloak_user_id)
        mapping = db.scalar(
            select(ExternalIdentityMapping).where(
                ExternalIdentityMapping.system == "northstar-directory",
                ExternalIdentityMapping.external_id == row.employee_number,
            )
        )
        if observed["enabled"]:
            raise IntegrationError("Keycloak account is still enabled.", retryable=True)
        if observed["groups"]:
            raise IntegrationError("Keycloak group membership is still present.", retryable=True)
        if mapping is None or mapping.active:
            raise IntegrationError("Downstream deprovisioning was not verified.", retryable=True)
        _save_observation(identity, observed, False, True, "leaver")
        return {"enabled": False, "downstream_active": False, "sessions": observed["session_count"]}

    try:
        return _run(db, workflow, [("detect", detect), ("disable", disable), ("sessions", sessions), ("entitlements", entitlements), ("downstream", downstream), ("verify", verify)])
    except IntegrationError:
        identity.account_state = "pending_deprovisioning"
        db.commit()
        raise


def retry_workflow(db, gateway: Gateway, workflow_id: str, *, password: str = "") -> LifecycleWorkflow:
    row = db.get(LifecycleWorkflow, workflow_id)
    if row is None:
        raise IntegrationError("Workflow was not found.", retryable=False, status=404)
    if row.workflow_type == "joiner":
        return run_joiner(db, gateway, row.employee_number, correlation_id=row.correlation_id, workflow_id=row.id, password=password)
    if row.workflow_type == "leaver":
        return run_leaver(db, gateway, row.employee_number, correlation_id=row.correlation_id, workflow_id=row.id)
    if row.workflow_type == "mover":
        destination = None
        for stage in row.stages:
            if stage["key"] == "detect" and stage.get("result"):
                destination = stage["result"].get("to")
        if destination is None:
            raise IntegrationError("Mover destination was not recorded.", retryable=False)
        return run_mover(db, gateway, row.employee_number, destination, correlation_id=row.correlation_id, workflow_id=row.id)
    raise IntegrationError("Unsupported workflow.", retryable=False)

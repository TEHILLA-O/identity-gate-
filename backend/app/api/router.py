import hashlib
import json
import secrets
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from policy.decision import decision, load_catalog, load_matrix
from policy.entitlements import access_paths, compare_paths, summarise
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.security import (
    Principal,
    current_principal,
    new_session,
    pkce_challenge,
    read_state,
    require,
    serializer,
    verifier,
)
from app.config import get_settings
from app.db import get_db
from app.keycloak.gateway import Gateway
from app.models import (
    AccessRequest,
    AuditEvent,
    BrowserSession,
    ConnectorTestRun,
    ControlDefinition,
    ControlEvaluation,
    FindingNote,
    GrantEvidence,
    HrEmployee,
    IdempotencyKey,
    IdentityReference,
    LifecycleWorkflow,
    PolicyException,
    ProvisioningAttempt,
    ReconciliationItem,
    ReconciliationRun,
    ReviewCampaign,
    ReviewItem,
    SecurityFinding,
    SegregationConflict,
)
from app.security.crypto import open_secret
from app.security.tokens import TokenError
from app.services.access import (
    create_campaign,
    create_request,
    decide_item,
    decide_request,
    reassign_item,
    reconcile,
    repair,
)
from app.services.posture import (
    evaluate_controls,
    evaluate_findings,
    ingest_events,
    record_audit,
    refresh_conflicts,
    verify_chain,
)
from app.services.reports import generate
from app.services.workflows import retry_workflow, run_joiner, run_leaver, run_mover
from app.util import iso, new_id, utcnow

api = APIRouter()


class JoinerIn(BaseModel):
    employee_number: str
    username: str
    given_name: str
    family_name: str
    email: str
    department: str
    title: str
    manager_username: str | None = None
    employment_type: str = "employee"
    classification: str = "standard"
    join_date: str
    cost_centre: str = "ENG-200"


class MoveIn(BaseModel):
    employee_number: str
    department: str


class LeaveIn(BaseModel):
    employee_number: str


class RequestIn(BaseModel):
    target: str
    application: str
    role: str
    justification: str = Field(min_length=8)
    duration_hours: int = Field(ge=1, le=24 * 90)


class DecisionIn(BaseModel):
    reason: str = Field(min_length=3)
    approve: bool = True


class ReviewIn(BaseModel):
    decision: str
    reason: str = Field(min_length=8)


class CampaignIn(BaseModel):
    name: str
    kind: str
    reviewer: str
    due_at: datetime
    scope: dict = {}


class ExceptionIn(BaseModel):
    rule_id: str
    subject: str
    justification: str = Field(min_length=8)
    compensating_control: str = Field(min_length=8)
    expires_at: datetime


class FindingIn(BaseModel):
    status: str
    note: str = ""


class SimulateIn(BaseModel):
    username: str
    application: str
    action: str


def _page(page: int, size: int) -> tuple[int, int]:
    return max(page, 1), min(max(size, 1), 100)


def _envelope(items, page: int, size: int, total: int) -> dict:
    return {"items": items, "page": page, "page_size": size, "total": total}


def _person(row: HrEmployee, identity: IdentityReference | None) -> dict:
    return {
        "employee_number": row.employee_number,
        "username": row.username,
        "name": f"{row.given_name} {row.family_name}",
        "email": row.email,
        "department": row.department,
        "title": row.title,
        "manager": row.manager_username,
        "employment_status": row.employment_status,
        "employment_type": row.employment_type,
        "classification": row.classification,
        "join_date": row.join_date,
        "departure_date": row.departure_date,
        "cost_centre": row.cost_centre,
        "access_expires_at": row.access_expires_at,
        "account_state": identity.account_state if identity else "pending_provisioning",
        "kc_enabled": identity.kc_enabled if identity else None,
        "keycloak_user_id": identity.keycloak_user_id if identity else None,
        "last_login_at": iso(identity.last_login_at) if identity else None,
        "mfa_enrolled": identity.mfa_enrolled if identity else False,
        "source": identity.source if identity else "northstar-hr",
        "observed_at": iso(identity.observed_at) if identity else None,
        "groups": identity.groups if identity else [],
        "session_count": identity.session_count if identity else 0,
    }


def _identity_for(db: Session, username: str) -> tuple[HrEmployee, IdentityReference]:
    person = db.scalar(select(HrEmployee).where(HrEmployee.username == username))
    if person is None:
        raise HTTPException(status_code=404, detail="Identity was not found.")
    identity = db.scalar(select(IdentityReference).where(IdentityReference.employee_number == person.employee_number))
    if identity is None:
        raise HTTPException(status_code=404, detail="Identity has no Keycloak reference.")
    return person, identity


def _paths(person: HrEmployee, identity: IdentityReference) -> list[dict]:
    return access_paths(
        identity.groups or [],
        identity.direct_client_roles or {},
        identity.direct_realm_roles or [],
        identity.effective_client_roles or {},
        identity.effective_realm_roles or [],
    )


def _idempotency(db: Session, request: Request, body: dict):
    key = request.headers.get("idempotency-key")
    if not key:
        return None
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
    existing = db.get(IdempotencyKey, key)
    if existing:
        if existing.request_hash != digest:
            raise HTTPException(status_code=409, detail="Idempotency key was reused with a different request.")
        return existing.response_json
    request.state.idempotency = (key, digest)
    return None


def _store_idempotency(db: Session, request: Request, payload: dict) -> None:
    pair = getattr(request.state, "idempotency", None)
    if not pair:
        return
    key, digest = pair
    db.add(IdempotencyKey(key=key, request_hash=digest, status_code=200, response_json=payload, created_at=utcnow()))


@api.get("/system/health")
def health(db: Session = Depends(get_db)):
    settings = get_settings()
    db.execute(select(1))
    keycloak = False
    downstream = False
    try:
        response = httpx.get(f"{settings.internal_realm}/.well-known/openid-configuration", timeout=3, trust_env=False)
        keycloak = response.status_code == 200
    except httpx.HTTPError:
        keycloak = False
    try:
        response = httpx.get(settings.downstream_scim_url.replace("/scim/v2", "/health"), timeout=3, trust_env=False)
        downstream = response.status_code == 200
    except httpx.HTTPError:
        downstream = False
    return {"status": "ok" if keycloak and downstream else "degraded", "database": True, "keycloak": keycloak, "downstream": downstream, "environment": settings.environment_name}


@api.get("/auth/login")
def login():
    settings = get_settings()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier_value = secrets.token_urlsafe(64)
    challenge = pkce_challenge(verifier_value)
    redirect_uri = f"{settings.public_app_url}/api/v1/auth/callback"
    url = (
        f"{settings.keycloak_public_url.rstrip('/')}/realms/{settings.keycloak_realm}/protocol/openid-connect/auth"
        f"?client_id={settings.oidc_client_id}&response_type=code&scope=openid%20profile%20email"
        f"&redirect_uri={redirect_uri}&state={state}&nonce={nonce}"
        f"&code_challenge={challenge}&code_challenge_method=S256"
    )
    response = RedirectResponse(url)
    response.set_cookie("ig_oidc", serializer().dumps({"state": state, "nonce": nonce, "verifier": verifier_value}), httponly=True, samesite="lax", secure=settings.cookie_secure, max_age=600, path="/")
    return response


@api.get("/auth/callback")
def callback(code: str, state: str, request: Request, db: Session = Depends(get_db)):
    settings = get_settings()
    saved = read_state(request.cookies.get("ig_oidc"))
    if saved.get("state") != state:
        raise HTTPException(status_code=400, detail="Login state does not match.")
    redirect_uri = f"{settings.public_app_url}/api/v1/auth/callback"
    token_response = httpx.post(
        f"{settings.internal_realm}/protocol/openid-connect/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": settings.oidc_client_id,
            "client_secret": settings.oidc_client_secret,
            "code_verifier": saved["verifier"],
        },
        timeout=20,
        trust_env=False,
    )
    if token_response.status_code != 200:
        raise HTTPException(status_code=401, detail="Token exchange failed.")
    body = token_response.json()
    try:
        identity = verifier().verify(body["id_token"], nonce=saved["nonce"])
        access = verifier().verify(body["access_token"])
        if access.get("preferred_username") and access.get("preferred_username") != identity.get("preferred_username"):
            raise HTTPException(status_code=401, detail="Access token subject does not match the identity token.")
    except TokenError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    if identity.get("azp") not in {None, settings.oidc_client_id}:
        raise HTTPException(status_code=401, detail="Token client does not match.")
    claims = {**identity, "realm_access": access.get("realm_access") or identity.get("realm_access")}
    row = new_session(db, claims, body["access_token"], body.get("refresh_token", ""), body["id_token"])
    record_audit(db, source="identitygate", event_type="LOGIN", actor=row.username, target="identitygate", outcome="success", correlation_id=request.headers.get("x-correlation-id"), metadata={"client": settings.oidc_client_id})
    response = RedirectResponse(settings.public_app_url)
    response.set_cookie("ig_session", row.id, httponly=True, samesite="lax", secure=settings.cookie_secure, path="/")
    response.delete_cookie("ig_oidc", path="/")
    return response


@api.post("/auth/logout")
def logout(request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    settings = get_settings()
    row = db.get(BrowserSession, principal.session_id) if principal.session_id else None
    hint = ""
    if row:
        hint = open_secret(settings.session_secret, row.id_token)
        db.delete(row)
    record_audit(db, source="identitygate", event_type="LOGOUT", actor=principal.username, target="identitygate", outcome="success", correlation_id=request.headers.get("x-correlation-id"), metadata={})
    url = (
        f"{settings.keycloak_public_url.rstrip('/')}/realms/{settings.keycloak_realm}/protocol/openid-connect/logout"
        f"?client_id={settings.oidc_client_id}&post_logout_redirect_uri={settings.public_app_url}&id_token_hint={hint}"
    )
    response = JSONResponse({"logout_url": url})
    response.delete_cookie("ig_session", path="/")
    return response


@api.get("/auth/me")
def me(principal: Principal = Depends(require("read"))):
    return {"username": principal.username, "roles": principal.roles, "csrf_token": principal.csrf, "permissions": sorted(_permissions(principal))}


def _permissions(principal: Principal) -> set[str]:
    from app.api.security import ROLE_PERMISSIONS

    held = set()
    for role in principal.roles:
        held |= ROLE_PERMISSIONS.get(role, set())
    return held


@api.get("/system/status")
def status(principal: Principal = Depends(require("read")), db: Session = Depends(get_db)):
    return health(db) | {
        "organisation": "Northstar Digital",
        "identities": db.query(HrEmployee).count(),
        "open_findings": db.query(SecurityFinding).filter(SecurityFinding.status.notin_(["resolved", "accepted"])).count(),
        "open_reviews": db.query(ReviewItem).filter(ReviewItem.status == "pending").count(),
        "policy_version": load_matrix()["version"],
    }


@api.get("/identities")
def identities(q: str = "", department: str = "", status: str = "", classification: str = "", page: int = 1, page_size: int = 25, principal: Principal = Depends(require("read")), db: Session = Depends(get_db)):
    page, size = _page(page, page_size)
    stmt = select(HrEmployee)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(HrEmployee.username.ilike(like), HrEmployee.email.ilike(like), HrEmployee.employee_number.ilike(like), HrEmployee.given_name.ilike(like), HrEmployee.family_name.ilike(like)))
    if department:
        stmt = stmt.where(HrEmployee.department == department)
    if status:
        stmt = stmt.where(HrEmployee.employment_status == status)
    if classification:
        stmt = stmt.where(HrEmployee.classification == classification)
    total = len(db.scalars(stmt).all())
    rows = db.scalars(stmt.order_by(HrEmployee.employee_number).offset((page - 1) * size).limit(size)).all()
    refs = {item.employee_number: item for item in db.scalars(select(IdentityReference)).all()}
    return _envelope([_person(row, refs.get(row.employee_number)) for row in rows], page, size, total)


@api.get("/identities/{username}")
def identity_detail(username: str, principal: Principal = Depends(require("read")), db: Session = Depends(get_db)):
    person, identity = _identity_for(db, username)
    paths = summarise(_paths(person, identity))
    grants = db.scalars(select(GrantEvidence).where(GrantEvidence.employee_number == person.employee_number)).all()
    requests = db.scalars(select(AccessRequest).where(AccessRequest.target == username)).all()
    findings = db.scalars(select(SecurityFinding).where(SecurityFinding.subject == username)).all()
    workflows = db.scalars(select(LifecycleWorkflow).where(LifecycleWorkflow.employee_number == person.employee_number).order_by(LifecycleWorkflow.created_at.desc())).all()
    return {"identity": _person(person, identity), "access": paths, "direct_client_roles": identity.direct_client_roles, "effective_client_roles": identity.effective_client_roles, "effective_realm_roles": identity.effective_realm_roles, "grants": [_grant(item) for item in grants], "requests": [_request(item) for item in requests], "findings": [_finding(item) for item in findings], "workflows": [_workflow(item) for item in workflows]}


@api.get("/access-paths")
def access_path(username: str, principal: Principal = Depends(require("read")), db: Session = Depends(get_db)):
    person, identity = _identity_for(db, username)
    return summarise(_paths(person, identity))


@api.get("/access-paths/compare")
def compare(left: str, right: str, principal: Principal = Depends(require("read")), db: Session = Depends(get_db)):
    left_person, left_identity = _identity_for(db, left)
    right_person, right_identity = _identity_for(db, right)
    return {"left": left, "right": right, **compare_paths(_paths(left_person, left_identity), _paths(right_person, right_identity))}


@api.get("/graph")
def graph(username: str = "", principal: Principal = Depends(require("read")), db: Session = Depends(get_db)):
    if not username:
        return _posture_graph(db)
    person, identity = _identity_for(db, username)
    return _focus_graph(person, identity, db)


@api.post("/lifecycle/joiners")
def joiner(body: JoinerIn, request: Request, principal: Principal = Depends(require("lifecycle:run")), db: Session = Depends(get_db)):
    cached = _idempotency(db, request, body.model_dump())
    if cached:
        return cached
    if db.get(HrEmployee, body.employee_number) or db.scalar(select(HrEmployee).where(HrEmployee.username == body.username)):
        raise HTTPException(status_code=409, detail="That employee number or username already exists.")
    row = HrEmployee(suppressed_groups=[], suppressed_roles=[], extra_groups=[], direct_roles=[], employment_status="active", departure_date=None, access_expires_at=None, updated_at=utcnow(), **body.model_dump())
    db.add(row)
    db.flush()
    workflow = run_joiner(db, Gateway(get_settings()), row.employee_number, correlation_id=_cid(request), onboarding=True, password=get_settings().demo_user_password)
    payload = _workflow(workflow)
    _store_idempotency(db, request, payload)
    record_audit(db, source="identitygate", event_type="JOINER", actor=principal.username, target=row.username, outcome=workflow.status, correlation_id=workflow.correlation_id, metadata={"employee_number": row.employee_number})
    return payload


@api.post("/lifecycle/movers")
def mover(body: MoveIn, request: Request, principal: Principal = Depends(require("lifecycle:run")), db: Session = Depends(get_db)):
    workflow = run_mover(db, Gateway(get_settings()), body.employee_number, body.department, correlation_id=_cid(request))
    record_audit(db, source="identitygate", event_type="MOVER", actor=principal.username, target=body.employee_number, outcome=workflow.status, correlation_id=workflow.correlation_id, metadata={"department": body.department})
    return _workflow(workflow)


@api.post("/lifecycle/leavers")
def leaver(body: LeaveIn, request: Request, principal: Principal = Depends(require("lifecycle:run")), db: Session = Depends(get_db)):
    workflow = run_leaver(db, Gateway(get_settings()), body.employee_number, correlation_id=_cid(request))
    record_audit(db, source="identitygate", event_type="LEAVER", actor=principal.username, target=body.employee_number, outcome=workflow.status, correlation_id=workflow.correlation_id, metadata={})
    return _workflow(workflow)


@api.get("/lifecycle")
def lifecycle(principal: Principal = Depends(require("read")), db: Session = Depends(get_db)):
    rows = db.scalars(select(LifecycleWorkflow).order_by(LifecycleWorkflow.created_at.desc()).limit(100)).all()
    return {"items": [_workflow(row) for row in rows]}


@api.post("/lifecycle/{workflow_id}/retry")
def retry(workflow_id: str, principal: Principal = Depends(require("lifecycle:run")), db: Session = Depends(get_db)):
    workflow = retry_workflow(db, Gateway(get_settings()), workflow_id, password=get_settings().demo_user_password)
    return _workflow(workflow)


@api.get("/provisioning/attempts")
def attempts(principal: Principal = Depends(require("read")), db: Session = Depends(get_db)):
    rows = db.scalars(select(ProvisioningAttempt).order_by(ProvisioningAttempt.created_at.desc()).limit(100)).all()
    return {"items": [{"id": row.id, "target": row.target_system, "operation": row.operation, "method": row.method, "path": row.path, "status": row.http_status, "outcome": row.outcome, "correlation_id": row.correlation_id, "duration_ms": row.duration_ms, "request": row.request_body, "response": row.response_body, "error": row.error_summary, "created_at": iso(row.created_at)} for row in rows]}


@api.post("/provisioning/reconcile")
def start_reconcile(principal: Principal = Depends(require("provision:run")), db: Session = Depends(get_db)):
    run = reconcile(db, Gateway(get_settings()))
    return {"id": run.id, "summary": run.summary, "desired_count": run.desired_count, "actual_count": run.actual_count}


@api.get("/provisioning/reconcile")
def list_reconcile(principal: Principal = Depends(require("read")), db: Session = Depends(get_db)):
    runs = db.scalars(select(ReconciliationRun).order_by(ReconciliationRun.created_at.desc()).limit(20)).all()
    return {"items": [{"id": row.id, "summary": row.summary, "desired_count": row.desired_count, "actual_count": row.actual_count, "created_at": iso(row.created_at)} for row in runs]}


@api.get("/provisioning/reconcile/{run_id}")
def reconcile_detail(run_id: str, principal: Principal = Depends(require("read")), db: Session = Depends(get_db)):
    run = db.get(ReconciliationRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Reconciliation run was not found.")
    items = db.scalars(select(ReconciliationItem).where(ReconciliationItem.run_id == run_id)).all()
    return {"id": run.id, "summary": run.summary, "items": [{"id": item.id, "external_id": item.external_id, "kind": item.kind, "desired": item.desired, "actual": item.actual, "status": item.status} for item in items]}


@api.post("/provisioning/reconcile/{run_id}/apply")
def apply_reconcile(run_id: str, item_ids: list[str], principal: Principal = Depends(require("provision:run")), db: Session = Depends(get_db)):
    return repair(db, Gateway(get_settings()), run_id, item_ids)


@api.post("/connectors/keycloak-scim/tests")
def scim_tests(principal: Principal = Depends(require("provision:run")), db: Session = Depends(get_db)):
    results = _scim_probe()
    row = ConnectorTestRun(id=new_id(), target="keycloak-scim", results=results, created_at=utcnow())
    db.add(row)
    return {"id": row.id, "results": results, "certification": "These are interoperability checks against the configured Keycloak SCIM API. They are not a protocol certification."}


@api.get("/access-requests")
def list_requests(principal: Principal = Depends(require("read")), db: Session = Depends(get_db)):
    rows = db.scalars(select(AccessRequest).order_by(AccessRequest.created_at.desc()).limit(200)).all()
    return {"items": [_request(row) for row in rows]}


@api.post("/access-requests")
def post_request(body: RequestIn, request: Request, principal: Principal = Depends(require("requests:create")), db: Session = Depends(get_db)):
    cached = _idempotency(db, request, body.model_dump())
    if cached:
        return cached
    row = create_request(db, principal.username, body.target, body.application, body.role, body.justification, body.duration_hours, _cid(request))
    payload = _request(row)
    _store_idempotency(db, request, payload)
    record_audit(db, source="identitygate", event_type="ACCESS_REQUEST", actor=principal.username, target=body.target, outcome=row.status, correlation_id=row.correlation_id, metadata={"application": body.application, "role": body.role})
    return payload


@api.post("/access-requests/{request_id}/decision")
def request_decision(request_id: str, body: DecisionIn, request: Request, principal: Principal = Depends(require("read")), db: Session = Depends(get_db)):
    row = decide_request(db, Gateway(get_settings()), request_id, principal.username, body.approve, body.reason)
    record_audit(db, source="identitygate", event_type="ACCESS_DECISION", actor=principal.username, target=row.target, outcome=row.status, correlation_id=row.correlation_id, metadata={"approve": body.approve, "role": row.role_name})
    return _request(row)


@api.get("/campaigns")
def campaigns(principal: Principal = Depends(require("read")), db: Session = Depends(get_db)):
    rows = db.scalars(select(ReviewCampaign).order_by(ReviewCampaign.created_at.desc())).all()
    return {"items": [_campaign(db, row) for row in rows]}


@api.post("/campaigns")
def post_campaign(body: CampaignIn, principal: Principal = Depends(require("reviews:manage")), db: Session = Depends(get_db)):
    due = body.due_at if body.due_at.tzinfo else body.due_at.replace(tzinfo=timezone.utc)
    row = create_campaign(db, name=body.name, kind=body.kind, reviewer=body.reviewer, due_at=due, scope=body.scope, actor=principal.username)
    return _campaign(db, row)


@api.get("/campaigns/{campaign_id}")
def campaign_detail(campaign_id: str, principal: Principal = Depends(require("read")), db: Session = Depends(get_db)):
    row = db.get(ReviewCampaign, campaign_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Campaign was not found.")
    items = db.scalars(select(ReviewItem).where(ReviewItem.campaign_id == campaign_id)).all()
    return {**_campaign(db, row), "items": [_item(item) for item in items]}


@api.post("/campaigns/items/{item_id}/decision")
def review_decision(item_id: str, body: ReviewIn, principal: Principal = Depends(require("reviews:decide")), db: Session = Depends(get_db)):
    item = decide_item(db, Gateway(get_settings()), item_id, principal.username, body.decision, body.reason)
    record_audit(db, source="identitygate", event_type="REVIEW_DECISION", actor=principal.username, target=item.username, outcome=item.status, correlation_id=item.id, metadata={"decision": body.decision, "remediation": item.remediation_status, "role": item.role_name})
    return _item(item)


@api.post("/campaigns/items/{item_id}/reassign")
def reassign(item_id: str, reviewer: str, principal: Principal = Depends(require("reviews:manage")), db: Session = Depends(get_db)):
    return _item(reassign_item(db, item_id, reviewer, principal.username))


@api.post("/policies/simulate")
def simulate(body: SimulateIn, principal: Principal = Depends(require("read")), db: Session = Depends(get_db)):
    person, identity = _identity_for(db, body.username)
    roles = set((identity.effective_client_roles or {}).get(body.application, []))
    result = decision(load_matrix(), body.application, body.action, roles)
    result["paths"] = [path for path in _paths(person, identity) if path["application"] == body.application and path["permission"] == body.action]
    return result


@api.get("/policies/matrix")
def matrix(principal: Principal = Depends(require("read"))):
    return {"matrix": load_matrix(), "catalog": load_catalog()}


@api.get("/sod/conflicts")
def conflicts(principal: Principal = Depends(require("read")), db: Session = Depends(get_db)):
    refresh_conflicts(db)
    rows = db.scalars(select(SegregationConflict).order_by(SegregationConflict.severity)).all()
    return {"items": [{"id": row.id, "rule_id": row.rule_id, "subject": row.subject, "severity": row.severity, "status": row.status, "explanation": row.explanation, "detail": row.detail} for row in rows]}


@api.post("/sod/exceptions")
def exception(body: ExceptionIn, principal: Principal = Depends(require("exceptions:write")), db: Session = Depends(get_db)):
    if principal.username == body.subject:
        raise HTTPException(status_code=403, detail="You cannot record an exception for your own conflict.")
    expires = body.expires_at if body.expires_at.tzinfo else body.expires_at.replace(tzinfo=timezone.utc)
    if expires <= utcnow():
        raise HTTPException(status_code=400, detail="Exception expiry must be in the future.")
    row = PolicyException(id=new_id(), rule_id=body.rule_id, subject=body.subject, justification=body.justification, approver=principal.username, compensating_control=body.compensating_control, state="active", expires_at=expires, created_at=utcnow())
    db.add(row)
    refresh_conflicts(db)
    record_audit(db, source="identitygate", event_type="SOD_EXCEPTION", actor=principal.username, target=body.subject, outcome="active", correlation_id=row.id, metadata={"rule_id": body.rule_id})
    return {"id": row.id, "status": "active"}


@api.get("/findings")
def findings(principal: Principal = Depends(require("read")), db: Session = Depends(get_db)):
    rows = db.scalars(select(SecurityFinding).order_by(SecurityFinding.priority_score.desc())).all()
    return {"items": [_finding(row) for row in rows], "weights": {"critical": 40, "high": 25, "medium": 12, "low": 5}, "note": "Priority scores add rule weights. They are not a probability and they do not label a person as malicious."}


@api.post("/findings/evaluate")
def run_findings(principal: Principal = Depends(require("findings:write")), db: Session = Depends(get_db)):
    refresh_conflicts(db)
    rows = evaluate_findings(db)
    return {"open": len(rows)}


@api.post("/findings/{finding_id}")
def update_finding(finding_id: str, body: FindingIn, principal: Principal = Depends(require("findings:write")), db: Session = Depends(get_db)):
    row = db.get(SecurityFinding, finding_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Finding was not found.")
    if body.status not in {"open", "acknowledged", "investigating", "remediation", "resolved", "accepted"}:
        raise HTTPException(status_code=400, detail="Unsupported finding status.")
    if body.status == "resolved" and row.rule_id in {"SOD_CONFLICT", "FAILED_DEPROVISION", "DEPARTED_DOWNSTREAM_ACTIVE"}:
        raise HTTPException(status_code=409, detail="This finding is resolved only when evaluation no longer observes the condition. Use accepted for a recorded risk acceptance.")
    row.status = "accepted" if body.status == "accepted" else body.status
    if body.status == "remediation":
        row.status = "remediation"
    if body.note:
        db.add(FindingNote(id=new_id(), finding_id=row.id, author=principal.username, body=body.note, created_at=utcnow()))
    row.updated_at = utcnow()
    return _finding(row)


@api.get("/audit-events")
def audit_events(actor: str = "", target: str = "", event_type: str = "", correlation_id: str = "", page: int = 1, page_size: int = 50, principal: Principal = Depends(require("read")), db: Session = Depends(get_db)):
    page, size = _page(page, page_size)
    stmt = select(AuditEvent)
    if actor:
        stmt = stmt.where(AuditEvent.actor == actor)
    if target:
        stmt = stmt.where(AuditEvent.target == target)
    if event_type:
        stmt = stmt.where(AuditEvent.event_type == event_type)
    if correlation_id:
        stmt = stmt.where(AuditEvent.correlation_id == correlation_id)
    total = len(db.scalars(stmt).all())
    rows = db.scalars(stmt.order_by(AuditEvent.occurred_at.desc()).offset((page - 1) * size).limit(size)).all()
    return _envelope([_event(row) for row in rows], page, size, total) | {"chain": verify_chain(db)}


@api.post("/audit-events/ingest")
def ingest(principal: Principal = Depends(require("findings:write")), db: Session = Depends(get_db)):
    added = ingest_events(db, Gateway(get_settings()))
    return {"ingested": added, "chain": verify_chain(db)}


@api.get("/controls")
def controls(principal: Principal = Depends(require("read")), db: Session = Depends(get_db)):
    definitions = db.scalars(select(ControlDefinition)).all()
    latest: dict[str, ControlEvaluation] = {}
    for row in db.scalars(select(ControlEvaluation).order_by(ControlEvaluation.evaluated_at.desc())).all():
        latest.setdefault(row.control_id, row)
    return {"items": [{"control_id": item.control_id, "framework": item.framework, "title": item.title, "objective": item.objective, "implementation": item.implementation, "iso_note": item.iso_note, "owner": item.owner, "evaluation": None if item.control_id not in latest else {"status": latest[item.control_id].status, "summary": latest[item.control_id].summary, "evidence": latest[item.control_id].evidence, "limitations": latest[item.control_id].limitations, "evaluated_at": iso(latest[item.control_id].evaluated_at)}} for item in definitions]}


@api.post("/controls/evaluate")
def run_controls(principal: Principal = Depends(require("reports:export")), db: Session = Depends(get_db)):
    rows = evaluate_controls(db, Gateway(get_settings()))
    return {"evaluated": [{"control_id": row.control_id, "status": row.status} for row in rows]}


@api.post("/reports/{report_type}")
def report(report_type: str, fmt: str = "json", principal: Principal = Depends(require("reports:export")), db: Session = Depends(get_db)):
    record = generate(db, report_type, fmt, get_settings().report_path)
    return {"id": record.id, "path": record.path, "summary": record.summary}


@api.get("/reports/{report_id}/download")
def download(report_id: str, principal: Principal = Depends(require("reports:export")), db: Session = Depends(get_db)):
    from app.models import ReportingRun

    row = db.get(ReportingRun, report_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Report was not found.")
    return FileResponse(row.path, filename=row.path.split("\\")[-1].split("/")[-1])


@api.get("/search")
def search(q: str = Query(min_length=1), principal: Principal = Depends(require("read")), db: Session = Depends(get_db)):
    like = f"%{q.lower()}%"
    people = db.scalars(select(HrEmployee).where(or_(HrEmployee.username.ilike(like), HrEmployee.family_name.ilike(like), HrEmployee.employee_number.ilike(like))).limit(8)).all()
    findings = db.scalars(select(SecurityFinding).where(SecurityFinding.title.ilike(like)).limit(5)).all()
    controls = db.scalars(select(ControlDefinition).where(or_(ControlDefinition.control_id.ilike(like), ControlDefinition.title.ilike(like))).limit(5)).all()
    return {
        "identities": [{"label": f"{row.given_name} {row.family_name}", "username": row.username, "kind": "identity"} for row in people],
        "findings": [{"label": row.title, "id": row.id, "kind": "finding"} for row in findings],
        "controls": [{"label": f"{row.control_id} {row.title}", "id": row.control_id, "kind": "control"} for row in controls],
        "actions": [
            {"label": "Open identity graph", "workspace": "graph"},
            {"label": "Start reconciliation", "workspace": "provisioning"},
            {"label": "Open access reviews", "workspace": "reviews"},
        ],
    }


@api.post("/system/expire")
def expire(principal: Principal = Depends(require("lifecycle:run")), db: Session = Depends(get_db)):
    from app.services.access import expire_due

    return {"revoked": expire_due(db, Gateway(get_settings()))}


def _cid(request: Request) -> str:
    return request.headers.get("x-correlation-id") or new_id()


def _workflow(row: LifecycleWorkflow) -> dict:
    return {"id": row.id, "type": row.workflow_type, "employee_number": row.employee_number, "status": row.status, "correlation_id": row.correlation_id, "stages": row.stages, "diff": row.diff, "created_at": iso(row.created_at), "updated_at": iso(row.updated_at)}


def _grant(row: GrantEvidence) -> dict:
    return {"id": row.id, "application": row.application, "role": row.role_name, "group": row.group_name, "source": row.source, "privileged": row.privileged, "approval_id": row.access_request_id, "expires_at": iso(row.expires_at), "revoked_at": iso(row.revoked_at)}


def _request(row: AccessRequest) -> dict:
    return {"id": row.id, "requester": row.requester, "target": row.target, "application": row.application, "role": row.role_name, "justification": row.justification, "duration_hours": row.duration_hours, "status": row.status, "steps": row.steps, "grant_id": row.grant_id, "created_at": iso(row.created_at)}


def _campaign(db: Session, row: ReviewCampaign) -> dict:
    items = db.scalars(select(ReviewItem).where(ReviewItem.campaign_id == row.id)).all()
    total = len(items)
    reviewed = len([item for item in items if item.status in {"approved", "revoked"}])
    return {"id": row.id, "name": row.name, "kind": row.kind, "scope": row.scope, "reviewer": row.reviewer, "due_at": iso(row.due_at), "status": row.status, "policy_version": row.policy_version, "total": total, "reviewed": reviewed, "pending": len([item for item in items if item.status == "pending"]), "approved": len([item for item in items if item.status == "approved"]), "revoked": len([item for item in items if item.status == "revoked"]), "remediation_succeeded": len([item for item in items if item.remediation_status == "removal_succeeded"]), "remediation_failed": len([item for item in items if item.remediation_status in {"removal_failed", "reconciliation_pending"}]), "progress": 0 if not total else round(reviewed / total * 100)}


def _item(row: ReviewItem) -> dict:
    return {"id": row.id, "username": row.username, "employee_number": row.employee_number, "application": row.application, "role": row.role_name, "grant_source": row.grant_source, "grant_group": row.grant_group, "privileged": row.privileged, "reviewer": row.reviewer, "status": row.status, "remediation_status": row.remediation_status, "snapshot": row.snapshot}


def _finding(row: SecurityFinding) -> dict:
    return {"id": row.id, "rule_id": row.rule_id, "severity": row.severity, "title": row.title, "subject": row.subject, "application": row.application, "status": row.status, "evidence": row.evidence, "priority_score": row.priority_score, "first_observed_at": iso(row.first_observed_at)}


def _event(row: AuditEvent) -> dict:
    return {"id": row.id, "source": row.source_system, "type": row.event_type, "actor": row.actor, "target": row.target, "outcome": row.outcome, "correlation_id": row.correlation_id, "occurred_at": iso(row.occurred_at), "metadata": row.metadata_json}


def _posture_graph(db: Session) -> dict:
    catalog = load_catalog()
    nodes = [{"id": "org", "kind": "organisation", "label": "Northstar Digital"}]
    edges = []
    for department, group in catalog["department_groups"].items():
        nodes.append({"id": f"dept:{department}", "kind": "department", "label": department})
        nodes.append({"id": f"group:{group}", "kind": "group", "label": group})
        edges.append({"id": f"e-{department}", "source": f"dept:{department}", "target": f"group:{group}", "kind": "birthright"})
        binding = catalog["groups"][group]
        for app in binding["clients"]:
            nodes.append({"id": f"app:{app}", "kind": "application", "label": app})
            edges.append({"id": f"e-{group}-{app}", "source": f"group:{group}", "target": f"app:{app}", "kind": "grants"})
    deduped = {node["id"]: node for node in nodes}
    return {"nodes": list(deduped.values()), "edges": edges}


def _focus_graph(person: HrEmployee, identity: IdentityReference, db: Session) -> dict:
    nodes = [{"id": f"user:{person.username}", "kind": "person", "label": f"{person.given_name} {person.family_name}", "subtitle": person.employee_number, "status": person.employment_status}]
    edges = []
    if person.department:
        nodes.append({"id": f"dept:{person.department}", "kind": "department", "label": person.department})
        edges.append({"id": "dept", "source": f"user:{person.username}", "target": f"dept:{person.department}", "kind": "member"})
    if person.manager_username:
        nodes.append({"id": f"manager:{person.manager_username}", "kind": "manager", "label": person.manager_username})
        edges.append({"id": "manager", "source": f"user:{person.username}", "target": f"manager:{person.manager_username}", "kind": "reports"})
    paths = _paths(person, identity)
    for path in paths:
        if path.get("group"):
            nodes.append({"id": f"group:{path['group']}", "kind": "group", "label": path["group"]})
            edges.append({"id": f"ug-{path['group']}", "source": f"user:{person.username}", "target": f"group:{path['group']}", "kind": "member"})
            role_id = f"role:{path['application']}:{path['role']}"
            nodes.append({"id": role_id, "kind": "role", "label": path["role"], "privileged": path["privileged"]})
            edges.append({"id": f"gr-{path['group']}-{role_id}", "source": f"group:{path['group']}", "target": role_id, "kind": "inherits", "privileged": path["privileged"]})
        else:
            role_id = f"role:{path['application']}:{path['role']}"
            nodes.append({"id": role_id, "kind": "role", "label": path["role"], "privileged": path["privileged"], "subtitle": path["source"]})
            edges.append({"id": f"direct-{role_id}", "source": f"user:{person.username}", "target": role_id, "kind": path["source"], "privileged": path["privileged"]})
        if path["permission"]:
            perm_id = f"perm:{path['application']}:{path['permission']}"
            app_id = f"app:{path['application']}"
            nodes.append({"id": app_id, "kind": "application", "label": path["application"]})
            nodes.append({"id": perm_id, "kind": "permission", "label": path["permission"]})
            edges.append({"id": f"rp-{role_id}-{perm_id}", "source": role_id, "target": perm_id, "kind": "permits"})
            edges.append({"id": f"pa-{perm_id}", "source": perm_id, "target": app_id, "kind": "protects"})
    for finding in db.scalars(select(SecurityFinding).where(SecurityFinding.subject == person.username, SecurityFinding.status.notin_(["resolved"]))).all():
        nodes.append({"id": f"finding:{finding.id}", "kind": "finding", "label": finding.title, "subtitle": finding.severity})
        edges.append({"id": f"f-{finding.id}", "source": f"finding:{finding.id}", "target": f"user:{person.username}", "kind": "affects"})
    deduped = {}
    for node in nodes:
        deduped[node["id"]] = node
    edge_ids = {}
    for edge in edges:
        edge_ids[edge["id"]] = edge
    return {"nodes": list(deduped.values()), "edges": list(edge_ids.values())}


def _scim_probe() -> list[dict]:
    settings = get_settings()
    gateway = Gateway(settings)
    results = []
    username = f"probe.{secrets.token_hex(4)}"
    created = None

    def record(name: str, passed: bool, detail: str = ""):
        results.append({"name": name, "passed": passed, "detail": detail})

    try:
        anonymous = httpx.get(f"{settings.scim_base}/Users", timeout=10, trust_env=False)
        record("unauthenticated request is rejected", anonymous.status_code == 401, str(anonymous.status_code))
        response = gateway.scim("GET", "/ServiceProviderConfig", operation="probe-config")
        record("service provider config", response.status_code == 200, str(response.status_code))
        body = {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": username, "active": True, "name": {"givenName": "Probe", "familyName": "User"}}
        created_response = gateway.scim("POST", "/Users", body=body, operation="probe-create")
        record("create user", created_response.status_code in {200, 201}, str(created_response.status_code))
        if created_response.status_code in {200, 201}:
            created = created_response.json()
            fetched = gateway.scim("GET", f"/Users/{created['id']}", operation="probe-get")
            record("retrieve user", fetched.status_code == 200 and fetched.json().get("userName") == username)
            filtered = gateway.scim("GET", "/Users", params={"filter": f'userName eq "{username}"'}, operation="probe-filter")
            record("filter user", filtered.status_code == 200 and any(item.get("userName") == username for item in filtered.json().get("Resources") or []))
            patched = gateway.scim("PATCH", f"/Users/{created['id']}", body={"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "active", "value": False}]}, operation="probe-patch")
            record("deactivate user", patched.status_code in {200, 204})
            duplicate = gateway.scim("POST", "/Users", body=body, operation="probe-duplicate")
            record("duplicate user is rejected", duplicate.status_code == 409, str(duplicate.status_code))
        group_name = f"probe-group-{secrets.token_hex(3)}"
        group_response = gateway.scim("POST", "/Groups", body={"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": group_name}, operation="probe-group", resource_type="Group")
        record("create group", group_response.status_code in {200, 201}, str(group_response.status_code))
        if created and group_response.status_code in {200, 201}:
            group = group_response.json()
            added = gateway.scim("PATCH", f"/Groups/{group['id']}", body={"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "add", "path": "members", "value": created["id"]}]}, operation="probe-member", resource_type="Group")
            record("add group member", added.status_code in {200, 204}, str(added.status_code))
            removed = gateway.scim("PATCH", f"/Groups/{group['id']}", body={"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "remove", "path": f'members[value eq "{created["id"]}"]'}]}, operation="probe-unmember", resource_type="Group")
            record("remove group member", removed.status_code in {200, 204}, str(removed.status_code))
            deleted_group = gateway.scim("DELETE", f"/Groups/{group['id']}", operation="probe-delete-group", resource_type="Group")
            record("delete group", deleted_group.status_code in {200, 204}, str(deleted_group.status_code))
        if created:
            deleted = gateway.scim("DELETE", f"/Users/{created['id']}", operation="probe-delete")
            record("delete user", deleted.status_code in {200, 204}, str(deleted.status_code))
    except Exception as exc:
        record("probe execution", False, str(exc)[:240])
    finally:
        gateway.close()
    return results



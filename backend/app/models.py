"""Operational and governance tables.

Keycloak remains authoritative for accounts, credentials, and sessions.
Rows here reference those accounts and store workflow state Keycloak does not.
"""

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Organisation(Base):
    __tablename__ = "organisations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Department(Base):
    __tablename__ = "departments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    organisation_id: Mapped[str] = mapped_column(ForeignKey("organisations.id"))
    name: Mapped[str] = mapped_column(String(80), unique=True)
    cost_centre: Mapped[str] = mapped_column(String(32))


class Application(Base):
    __tablename__ = "applications"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(120), unique=True)
    name: Mapped[str] = mapped_column(String(200))
    base_url: Mapped[str] = mapped_column(String(300))
    owner_username: Mapped[str | None] = mapped_column(String(120))


class HrEmployee(Base):
    __tablename__ = "hr_employees"
    employee_number: Mapped[str] = mapped_column(String(32), primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    given_name: Mapped[str] = mapped_column(String(120))
    family_name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(254))
    department: Mapped[str] = mapped_column(String(80), index=True)
    title: Mapped[str] = mapped_column(String(160))
    manager_username: Mapped[str | None] = mapped_column(String(128))
    employment_status: Mapped[str] = mapped_column(String(32), index=True)
    employment_type: Mapped[str] = mapped_column(String(32))
    join_date: Mapped[str] = mapped_column(String(32))
    departure_date: Mapped[str | None] = mapped_column(String(32))
    cost_centre: Mapped[str] = mapped_column(String(32))
    classification: Mapped[str] = mapped_column(String(32))
    access_expires_at: Mapped[str | None] = mapped_column(String(40))
    extra_groups: Mapped[list] = mapped_column(JSON)
    direct_roles: Mapped[list] = mapped_column(JSON)
    suppressed_groups: Mapped[list] = mapped_column(JSON, default=list)
    suppressed_roles: Mapped[list] = mapped_column(JSON, default=list)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IdentityReference(Base):
    __tablename__ = "identity_references"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    employee_number: Mapped[str] = mapped_column(ForeignKey("hr_employees.employee_number"), unique=True)
    keycloak_user_id: Mapped[str | None] = mapped_column(String(64), unique=True)
    username: Mapped[str] = mapped_column(String(128), index=True)
    account_state: Mapped[str] = mapped_column(String(40), index=True)
    kc_enabled: Mapped[bool | None] = mapped_column(Boolean)
    source: Mapped[str] = mapped_column(String(40), default="northstar-hr")
    groups: Mapped[list] = mapped_column(JSON, default=list)
    direct_client_roles: Mapped[dict] = mapped_column(JSON, default=dict)
    direct_realm_roles: Mapped[list] = mapped_column(JSON, default=list)
    effective_client_roles: Mapped[dict] = mapped_column(JSON, default=dict)
    effective_realm_roles: Mapped[list] = mapped_column(JSON, default=list)
    mfa_enrolled: Mapped[bool] = mapped_column(Boolean, default=False)
    session_count: Mapped[int] = mapped_column(Integer, default=0)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ExternalIdentityMapping(Base):
    __tablename__ = "external_identity_mappings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    employee_number: Mapped[str] = mapped_column(String(32), index=True)
    system: Mapped[str] = mapped_column(String(80))
    external_id: Mapped[str] = mapped_column(String(128))
    resource_id: Mapped[str | None] = mapped_column(String(128))
    active: Mapped[bool | None] = mapped_column(Boolean)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint("system", "external_id", name="uq_external_system"),)


class LifecycleWorkflow(Base):
    __tablename__ = "lifecycle_workflows"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workflow_type: Mapped[str] = mapped_column(String(32), index=True)
    employee_number: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    correlation_id: Mapped[str] = mapped_column(String(64), index=True)
    stages: Mapped[list] = mapped_column(JSON)
    diff: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ProvisioningJob(Base):
    __tablename__ = "provisioning_jobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workflow_id: Mapped[str | None] = mapped_column(String(36), index=True)
    stage_key: Mapped[str | None] = mapped_column(String(64))
    target_system: Mapped[str] = mapped_column(String(80))
    resource_type: Mapped[str] = mapped_column(String(40))
    operation: Mapped[str] = mapped_column(String(40))
    external_id: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=5)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    correlation_id: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ProvisioningAttempt(Base):
    __tablename__ = "provisioning_attempts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    job_id: Mapped[str | None] = mapped_column(String(36), index=True)
    correlation_id: Mapped[str] = mapped_column(String(64), index=True)
    target_system: Mapped[str] = mapped_column(String(80))
    resource_type: Mapped[str] = mapped_column(String(40))
    operation: Mapped[str] = mapped_column(String(40))
    method: Mapped[str] = mapped_column(String(12))
    path: Mapped[str] = mapped_column(String(400))
    external_id: Mapped[str | None] = mapped_column(String(128))
    resource_id: Mapped[str | None] = mapped_column(String(128))
    http_status: Mapped[int | None] = mapped_column(Integer)
    outcome: Mapped[str] = mapped_column(String(32))
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    request_body: Mapped[dict | list | None] = mapped_column(JSON)
    response_body: Mapped[dict | list | str | None] = mapped_column(JSON)
    error_summary: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReconciliationRun(Base):
    __tablename__ = "provisioning_reconciliation_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    system: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(32))
    desired_count: Mapped[int] = mapped_column(Integer, default=0)
    actual_count: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReconciliationItem(Base):
    __tablename__ = "reconciliation_items"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("provisioning_reconciliation_runs.id"), index=True)
    external_id: Mapped[str | None] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(40))
    desired: Mapped[dict | None] = mapped_column(JSON)
    actual: Mapped[dict | None] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(32), default="open")


class GrantEvidence(Base):
    __tablename__ = "entitlement_grant_evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    employee_number: Mapped[str] = mapped_column(String(32), index=True)
    source: Mapped[str] = mapped_column(String(40))
    application: Mapped[str] = mapped_column(String(120))
    role_name: Mapped[str] = mapped_column(String(120))
    group_name: Mapped[str | None] = mapped_column(String(120))
    access_request_id: Mapped[str | None] = mapped_column(String(36))
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    correlation_id: Mapped[str] = mapped_column(String(64))


class EntitlementSnapshot(Base):
    __tablename__ = "entitlement_snapshots"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    employee_number: Mapped[str] = mapped_column(String(32), index=True)
    reason: Mapped[str] = mapped_column(String(80))
    payload: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AccessRequest(Base):
    __tablename__ = "access_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    requester: Mapped[str] = mapped_column(String(128))
    target: Mapped[str] = mapped_column(String(128), index=True)
    application: Mapped[str] = mapped_column(String(120))
    role_name: Mapped[str] = mapped_column(String(120))
    justification: Mapped[str] = mapped_column(Text)
    duration_hours: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(32), index=True)
    steps: Mapped[list] = mapped_column(JSON)
    grant_id: Mapped[str | None] = mapped_column(String(36))
    correlation_id: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AccessApproval(Base):
    __tablename__ = "access_approvals"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    request_id: Mapped[str] = mapped_column(ForeignKey("access_requests.id"), index=True)
    step_kind: Mapped[str] = mapped_column(String(40))
    approver: Mapped[str] = mapped_column(String(128))
    decision: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(Text, default="")
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReviewCampaign(Base):
    __tablename__ = "review_campaigns"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(40))
    scope: Mapped[dict] = mapped_column(JSON)
    reviewer: Mapped[str] = mapped_column(String(128))
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), index=True)
    policy_version: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReviewItem(Base):
    __tablename__ = "review_items"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("review_campaigns.id"), index=True)
    employee_number: Mapped[str] = mapped_column(String(32), index=True)
    username: Mapped[str] = mapped_column(String(128))
    application: Mapped[str] = mapped_column(String(120))
    role_name: Mapped[str] = mapped_column(String(120))
    grant_source: Mapped[str] = mapped_column(String(40))
    grant_group: Mapped[str | None] = mapped_column(String(120))
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    reviewer: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), default="pending")
    remediation_status: Mapped[str] = mapped_column(String(40), default="not_required")
    snapshot: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReviewDecision(Base):
    __tablename__ = "review_decisions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    item_id: Mapped[str] = mapped_column(ForeignKey("review_items.id"), index=True)
    campaign_id: Mapped[str] = mapped_column(String(36), index=True)
    reviewer: Mapped[str] = mapped_column(String(128))
    decision: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(Text)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RemediationTask(Base):
    __tablename__ = "remediation_tasks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source_type: Mapped[str] = mapped_column(String(40))
    source_id: Mapped[str] = mapped_column(String(36), index=True)
    employee_number: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(32))
    detail: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SegregationConflict(Base):
    __tablename__ = "segregation_conflicts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(40), index=True)
    rule_version: Mapped[int] = mapped_column(Integer)
    subject: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(32))
    explanation: Mapped[str] = mapped_column(Text)
    detail: Mapped[dict] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PolicyException(Base):
    __tablename__ = "policy_exceptions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(40), index=True)
    subject: Mapped[str] = mapped_column(String(128), index=True)
    justification: Mapped[str] = mapped_column(Text)
    approver: Mapped[str] = mapped_column(String(128))
    compensating_control: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(32))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SecurityFinding(Base):
    __tablename__ = "security_findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(80), index=True)
    severity: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(240))
    subject: Mapped[str | None] = mapped_column(String(128), index=True)
    application: Mapped[str | None] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(40), index=True)
    evidence: Mapped[dict] = mapped_column(JSON)
    priority_score: Mapped[int] = mapped_column(Integer, default=0)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (UniqueConstraint("rule_id", "subject", "application", name="uq_finding_identity"),)


class FindingNote(Base):
    __tablename__ = "finding_notes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("security_findings.id"), index=True)
    author: Mapped[str] = mapped_column(String(128))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ControlDefinition(Base):
    __tablename__ = "security_control_definitions"
    control_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    framework: Mapped[str] = mapped_column(String(80))
    title: Mapped[str] = mapped_column(String(200))
    objective: Mapped[str] = mapped_column(Text)
    implementation: Mapped[str] = mapped_column(Text)
    iso_note: Mapped[str] = mapped_column(Text, default="")
    owner: Mapped[str] = mapped_column(String(128))


class ControlEvaluation(Base):
    __tablename__ = "control_evaluations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    control_id: Mapped[str] = mapped_column(ForeignKey("security_control_definitions.control_id"), index=True)
    status: Mapped[str] = mapped_column(String(32))
    summary: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list] = mapped_column(JSON)
    limitations: Mapped[str] = mapped_column(Text)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source_system: Mapped[str] = mapped_column(String(40), index=True)
    source_reference: Mapped[str] = mapped_column(String(128))
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    actor: Mapped[str | None] = mapped_column(String(128), index=True)
    target: Mapped[str | None] = mapped_column(String(200), index=True)
    outcome: Mapped[str] = mapped_column(String(32))
    correlation_id: Mapped[str | None] = mapped_column(String(64), index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    metadata_json: Mapped[dict] = mapped_column(JSON)
    prev_hash: Mapped[str] = mapped_column(String(64))
    row_hash: Mapped[str] = mapped_column(String(64))
    __table_args__ = (UniqueConstraint("source_system", "source_reference", name="uq_audit_source"),)


class ReportingRun(Base):
    __tablename__ = "reporting_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    report_type: Mapped[str] = mapped_column(String(80))
    fmt: Mapped[str] = mapped_column(String(12))
    path: Mapped[str] = mapped_column(String(500))
    summary: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BrowserSession(Base):
    __tablename__ = "browser_sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    subject: Mapped[str] = mapped_column(String(64), index=True)
    username: Mapped[str] = mapped_column(String(128))
    email: Mapped[str] = mapped_column(String(254), default="")
    roles: Mapped[list] = mapped_column(JSON)
    access_token: Mapped[str] = mapped_column(Text)
    refresh_token: Mapped[str] = mapped_column(Text)
    id_token: Mapped[str] = mapped_column(Text)
    access_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IdempotencyKey(Base):
    __tablename__ = "idempotency_keys"
    key: Mapped[str] = mapped_column(String(120), primary_key=True)
    request_hash: Mapped[str] = mapped_column(String(64))
    status_code: Mapped[int] = mapped_column(Integer)
    response_json: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ConnectorTestRun(Base):
    __tablename__ = "connector_test_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target: Mapped[str] = mapped_column(String(80))
    results: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

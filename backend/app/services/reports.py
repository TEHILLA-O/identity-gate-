"""Evidence exports. These are internal assurance reports, not certifications."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from openpyxl import Workbook
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from sqlalchemy import select

from app.models import (
    AuditEvent,
    ControlDefinition,
    ControlEvaluation,
    GrantEvidence,
    LifecycleWorkflow,
    ReportingRun,
    SegregationConflict,
)
from app.util import new_id, utcnow


def generate(db, report_type: str, fmt: str, directory: Path) -> ReportingRun:
    rows, notes = _rows(db, report_type)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = utcnow().strftime("%Y%m%d%H%M%S")
    path = directory / f"{report_type}-{stamp}.{fmt}"
    if fmt == "json":
        path.write_text(json.dumps({"report_type": report_type, "generated_at": utcnow().isoformat(), "notes": notes, "rows": rows}, indent=2, default=str), encoding="utf-8")
    elif fmt == "csv":
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()) if rows else ["empty"])
            writer.writeheader()
            writer.writerows(rows)
    elif fmt == "xlsx":
        book = Workbook()
        sheet = book.active
        sheet.title = report_type[:31]
        headers = list(rows[0].keys()) if rows else ["empty"]
        sheet.append(headers)
        for row in rows:
            sheet.append([row.get(header) for header in headers])
        book.save(path)
    elif fmt == "pdf":
        _pdf(path, report_type, notes, rows)
    else:
        raise ValueError("Unsupported report format.")
    record = ReportingRun(id=new_id(), report_type=report_type, fmt=fmt, path=str(path), summary={"rows": len(rows), "generated_at": utcnow().isoformat(), "notes": notes}, created_at=utcnow())
    db.add(record)
    db.flush()
    return record


def _rows(db, report_type: str) -> tuple[list[dict], str]:
    if report_type == "controls":
        latest: dict[str, ControlEvaluation] = {}
        for row in db.scalars(select(ControlEvaluation).order_by(ControlEvaluation.evaluated_at.desc())).all():
            latest.setdefault(row.control_id, row)
        definitions = {row.control_id: row for row in db.scalars(select(ControlDefinition)).all()}
        rows = []
        for control_id, evaluation in latest.items():
            definition = definitions.get(control_id)
            rows.append({
                "control_id": control_id,
                "title": definition.title if definition else "",
                "status": evaluation.status,
                "summary": evaluation.summary,
                "limitations": evaluation.limitations,
                "evaluated_at": evaluation.evaluated_at.isoformat(),
            })
        return rows, "Illustrative control assessment. Not an attestation, certification, or authorisation to operate."
    if report_type == "privileged":
        rows = [
            {"employee_number": row.employee_number, "application": row.application, "role": row.role_name, "source": row.source, "approval_id": row.access_request_id or "", "expires_at": row.expires_at.isoformat() if row.expires_at else ""}
            for row in db.scalars(select(GrantEvidence).where(GrantEvidence.privileged.is_(True), GrantEvidence.revoked_at.is_(None))).all()
        ]
        return rows, "Privileged grants currently recorded by IdentityGate."
    if report_type == "lifecycle":
        rows = [{"id": row.id, "type": row.workflow_type, "employee_number": row.employee_number, "status": row.status, "updated_at": row.updated_at.isoformat()} for row in db.scalars(select(LifecycleWorkflow).order_by(LifecycleWorkflow.created_at.desc())).all()]
        return rows, "Workflow status is taken from recorded stages. Failed downstream steps stay failed."
    if report_type == "sod":
        rows = [{"rule_id": row.rule_id, "subject": row.subject, "severity": row.severity, "status": row.status, "explanation": row.explanation} for row in db.scalars(select(SegregationConflict)).all()]
        return rows, "Excepted conflicts remain listed. An exception does not delete the conflict."
    if report_type == "authentication":
        rows = [{"occurred_at": row.occurred_at.isoformat(), "type": row.event_type, "actor": row.actor or "", "target": row.target or "", "outcome": row.outcome, "source": row.source_system} for row in db.scalars(select(AuditEvent).where(AuditEvent.event_type.in_(["LOGIN", "LOGIN_ERROR", "LOGOUT"])).order_by(AuditEvent.occurred_at.desc()).limit(500)).all()]
        return rows, "Authentication events ingested from Keycloak. Tokens are not included."
    raise ValueError("Unknown report type.")


def _pdf(path: Path, report_type: str, notes: str, rows: list[dict]) -> None:
    styles = getSampleStyleSheet()
    story = [
        Paragraph("IdentityGate evidence report", styles["Title"]),
        Spacer(1, 8),
        Paragraph(report_type, styles["Heading2"]),
        Paragraph(notes, styles["Normal"]),
        Paragraph("Northstar Digital is a fictional organisation. This document is not an ISO, NIST, or FedRAMP certification.", styles["Italic"]),
        Spacer(1, 12),
    ]
    for row in rows[:80]:
        text = " | ".join(f"{key}: {value}" for key, value in row.items())
        story.append(Paragraph(text, styles["Normal"]))
        story.append(Spacer(1, 4))
    if len(rows) > 80:
        story.append(Paragraph(f"{len(rows) - 80} additional rows are included in the JSON and CSV exports.", styles["Normal"]))
    SimpleDocTemplate(str(path), pagesize=A4, title=f"IdentityGate {report_type}").build(story)

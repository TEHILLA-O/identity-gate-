from datetime import timedelta, timezone

from sqlalchemy import select

from app.config import get_settings
from app.db import SessionLocal
from app.keycloak.errors import IntegrationError
from app.keycloak.gateway import Gateway
from app.models import LifecycleWorkflow
from app.services.access import expire_due
from app.services.posture import ingest_events
from app.services.workflows import retry_workflow
from app.util import utcnow


def tick() -> None:
    settings = get_settings()
    db = SessionLocal()
    gateway = Gateway(settings)
    try:
        if settings.auto_expire:
            expire_due(db, gateway)
        try:
            ingest_events(db, gateway)
        except IntegrationError:
            pass
        now = utcnow()
        for workflow in db.scalars(select(LifecycleWorkflow).where(LifecycleWorkflow.status == "failed")).all():
            failed = next((stage for stage in workflow.stages if stage["status"] == "failed" and stage.get("retryable")), None)
            if failed is None or int(failed.get("attempts") or 1) >= 5:
                continue
            delay = min(60, 2 ** int(failed.get("attempts") or 1))
            updated = workflow.updated_at
            if updated.tzinfo is None:
                updated = updated.replace(tzinfo=timezone.utc)
            if updated + timedelta(seconds=delay) > now:
                continue
            try:
                retry_workflow(db, gateway, workflow.id, password=settings.demo_user_password)
            except IntegrationError:
                db.commit()
        db.commit()
    finally:
        gateway.close()
        db.close()

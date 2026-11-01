"""Load Northstar Digital and execute real provisioning workflows."""

from __future__ import annotations

import json
from datetime import timedelta

from policy.decision import load_catalog
from sqlalchemy import select

from app.config import get_settings
from app.db import Base, SessionLocal, engine
from app.keycloak.gateway import Gateway
from app.keycloak.realm_setup import RealmSetup
from app.models import Application, Department, HrEmployee, Organisation, ReviewCampaign
from app.services.access import create_campaign
from app.services.posture import (
    evaluate_controls,
    evaluate_findings,
    ingest_events,
    refresh_conflicts,
    seed_controls,
)
from app.services.workflows import run_joiner, run_leaver
from app.util import new_id, utcnow


def ordered(people: list[dict]) -> list[dict]:
    remaining = {person["username"]: person for person in people}
    done: set[str] = set()
    result = []
    while remaining:
        ready = [person for person in remaining.values() if not person["manager_username"] or person["manager_username"] in done]
        if not ready:
            raise RuntimeError("HR manager relationships contain a cycle.")
        for person in sorted(ready, key=lambda item: item["employee_number"]):
            result.append(person)
            done.add(person["username"])
            remaining.pop(person["username"])
    return result


def upsert_employee(db, person: dict) -> HrEmployee:
    row = db.get(HrEmployee, person["employee_number"])
    if row is None:
        row = HrEmployee(employee_number=person["employee_number"], suppressed_groups=[], suppressed_roles=[])
        db.add(row)
    for field in (
        "username",
        "given_name",
        "family_name",
        "email",
        "department",
        "title",
        "manager_username",
        "employment_status",
        "employment_type",
        "join_date",
        "departure_date",
        "cost_centre",
        "classification",
        "access_expires_at",
    ):
        setattr(row, field, person.get(field))
    row.extra_groups = person.get("extra_groups") or []
    row.direct_roles = person.get("direct_roles") or []
    row.suppressed_groups = row.suppressed_groups or []
    row.suppressed_roles = row.suppressed_roles or []
    row.updated_at = utcnow()
    return row


def seed_reference(db) -> None:
    catalog = load_catalog()
    org = db.scalar(select(Organisation).where(Organisation.name == "Northstar Digital"))
    if org is None:
        org = Organisation(id=new_id(), name="Northstar Digital", created_at=utcnow())
        db.add(org)
        db.flush()
    centres = {
        "Engineering": "ENG-200",
        "Finance": "FIN-310",
        "Sales": "SAL-420",
        "Human Resources": "HR-150",
        "Operations": "OPS-600",
        "Security": "SEC-100",
    }
    for name, centre in centres.items():
        if db.scalar(select(Department).where(Department.name == name)) is None:
            db.add(Department(id=new_id(), organisation_id=org.id, name=name, cost_centre=centre))
    apps = [
        ("northstar-finance", "Northstar Finance", "http://localhost:8101", catalog["application_owners"]["northstar-finance"]),
        ("northstar-projects", "Northstar Projects", "http://localhost:8102", catalog["application_owners"]["northstar-projects"]),
    ]
    for client_id, name, url, owner in apps:
        if db.scalar(select(Application).where(Application.client_id == client_id)) is None:
            db.add(Application(id=new_id(), client_id=client_id, name=name, base_url=url, owner_username=owner))
    seed_controls(db)
    db.commit()


def main() -> None:
    settings = get_settings()
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    setup = RealmSetup(settings)
    try:
        setup.wait()
        setup.authenticate()
        setup.configure()
    finally:
        setup.close()
    db = SessionLocal()
    gateway = Gateway(settings)
    try:
        seed_reference(db)
        people = json.loads((settings.data_path / "people.json").read_text(encoding="utf-8"))["people"]
        for person in ordered(people):
            row = upsert_employee(db, person)
            db.commit()
            if person["employment_status"] == "departed":
                run_joiner(db, gateway, row.employee_number, correlation_id=new_id(), active=True, password=settings.demo_user_password)
                run_leaver(db, gateway, row.employee_number, correlation_id=new_id())
            else:
                run_joiner(db, gateway, row.employee_number, correlation_id=new_id(), password=settings.demo_user_password)
        if db.scalar(select(ReviewCampaign).where(ReviewCampaign.name == "Finance application access")) is None:
            create_campaign(
                db,
                name="Finance application access",
                kind="application",
                reviewer="priya.nair",
                due_at=utcnow() + timedelta(days=14),
                scope={"application": "northstar-finance"},
                actor="amira.shah",
            )
            db.commit()
        refresh_conflicts(db)
        evaluate_findings(db)
        try:
            ingest_events(db, gateway)
        except Exception as exc:
            print(f"event ingestion deferred: {exc}")
        evaluate_controls(db, gateway)
        db.commit()
        print("IdentityGate bootstrap completed.")
    finally:
        gateway.close()
        db.close()


if __name__ == "__main__":
    main()

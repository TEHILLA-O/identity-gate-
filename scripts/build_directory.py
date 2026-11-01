"""Deterministic Northstar Digital directory. Fictional identities only."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "people.json"

COST = {
    "Engineering": "ENG-200",
    "Finance": "FIN-310",
    "Sales": "SAL-420",
    "Human Resources": "HR-150",
    "Operations": "OPS-600",
    "Security": "SEC-100",
}


def person(
    number: int,
    username: str,
    given: str,
    family: str,
    department: str,
    title: str,
    manager: str | None,
    *,
    status: str = "active",
    employment_type: str = "employee",
    classification: str = "standard",
    join_date: str = "2022-03-01",
    departure_date: str | None = None,
    access_expires_at: str | None = None,
    extra_groups: list | None = None,
    direct_roles: list | None = None,
) -> dict:
    return {
        "employee_number": f"NS-{10000 + number}",
        "username": username,
        "given_name": given,
        "family_name": family,
        "email": f"{username}@northstar.example",
        "department": department,
        "title": title,
        "manager_username": manager,
        "employment_status": status,
        "employment_type": employment_type,
        "join_date": join_date,
        "departure_date": departure_date,
        "cost_centre": COST[department],
        "classification": classification,
        "access_expires_at": access_expires_at,
        "extra_groups": extra_groups or [],
        "direct_roles": direct_roles or [],
    }


def grant(group: str, approver: str | None, justification: str, approved: bool = True) -> dict:
    return {
        "group": group,
        "approved": approved,
        "approver": approver,
        "justification": justification,
    }


PEOPLE = [
    person(1, "amira.shah", "Amira", "Shah", "Security", "Director of Identity Security", None,
           classification="privileged", join_date="2016-02-01",
           extra_groups=[grant("identity-administrators", "helen.cho", "Appointed owner of the identity platform.")]),
    person(2, "elias.morin", "Elias", "Morin", "Security", "Security Engineer", "amira.shah", join_date="2021-06-14"),
    person(3, "nora.feld", "Nora", "Feld", "Security", "Security Analyst", "amira.shah", join_date="2023-01-09"),
    person(4, "samir.dalal", "Samir", "Dalal", "Security", "Detection Engineer", "amira.shah", join_date="2020-11-02"),
    person(5, "yara.hassan", "Yara", "Hassan", "Security", "Security Assurance Analyst", "amira.shah", join_date="2022-08-22"),
    person(6, "victor.lange", "Victor", "Lange", "Security", "IAM Engineer", "amira.shah", join_date="2019-05-20"),
    person(7, "celeste.ng", "Celeste", "Ng", "Security", "Privileged Access Analyst", "amira.shah", join_date="2024-02-12"),
    person(8, "priya.nair", "Priya", "Nair", "Finance", "Finance Manager", None,
           classification="privileged", join_date="2017-09-01",
           extra_groups=[
               grant("finance-approvers", "amira.shah", "Payment approval authority for the finance function."),
               grant("identity-reviewers", "amira.shah", "Department access reviewer for Finance."),
           ]),
    person(9, "elena.vasquez", "Elena", "Vasquez", "Finance", "Finance Analyst", "priya.nair",
           join_date="2021-04-19",
           extra_groups=[grant("finance-analysts", "priya.nair", "Prepares management reports. Cannot approve payments.")],
           direct_roles=[{
               "client": "northstar-projects",
               "role": "project-contributor",
               "approved": True,
               "approver": "devon.cho",
               "justification": "Time-boxed support for the billing integration project.",
               "expires_at": "2026-11-20T17:00:00Z",
           }]),
    person(10, "marcus.hale", "Marcus", "Hale", "Finance", "Payments Lead", "priya.nair",
           classification="privileged", join_date="2018-01-15",
           extra_groups=[
               grant("finance-analysts", "priya.nair", "Owns payment batch preparation."),
               grant("finance-approvers", "amira.shah", "Legacy approval right retained after a role change."),
           ]),
    person(11, "david.okeke", "David", "Okeke", "Finance", "Finance Systems Administrator", "priya.nair",
           classification="privileged", join_date="2019-10-07",
           extra_groups=[grant("finance-administrators", "amira.shah", "Configures the finance application. Cannot approve payments.")]),
    person(12, "ruth.keller", "Ruth", "Keller", "Finance", "General Ledger Accountant", "priya.nair", join_date="2020-03-03"),
    person(13, "benicio.alves", "Benicio", "Alves", "Finance", "Revenue Analyst", "priya.nair", join_date="2023-07-11"),
    person(14, "hana.sato", "Hana", "Sato", "Finance", "Billing Specialist", "priya.nair", join_date="2022-12-01"),
    person(15, "isaac.moreau", "Isaac", "Moreau", "Finance", "Treasury Analyst", "priya.nair", join_date="2024-05-06"),
    person(16, "ruth.adebayo", "Ruth", "Adebayo", "Sales", "Sales Director", None, classification="manager", join_date="2015-08-18"),
    person(17, "leo.marin", "Leo", "Marin", "Sales", "Account Executive", "ruth.adebayo", join_date="2021-02-02"),
    person(18, "fatima.diallo", "Fatima", "Diallo", "Sales", "Account Executive", "ruth.adebayo", join_date="2022-05-16"),
    person(19, "chris.novak", "Chris", "Novak", "Sales", "Sales Operations Analyst", "ruth.adebayo", join_date="2020-09-09"),
    person(20, "aisha.rahman", "Aisha", "Rahman", "Sales", "Customer Advisor", "ruth.adebayo", join_date="2023-03-27"),
    person(21, "peter.holm", "Peter", "Holm", "Sales", "Enterprise Seller", "ruth.adebayo", join_date="2019-01-14"),
    person(22, "grace.ibe", "Grace", "Ibe", "Sales", "Sales Coordinator", "ruth.adebayo", join_date="2024-08-05"),
    person(23, "oscar.lind", "Oscar", "Lind", "Sales", "Solutions Consultant", "ruth.adebayo", join_date="2021-11-30"),
    person(24, "sofia.berg", "Sofia", "Berg", "Human Resources", "HR Manager", None, classification="manager", join_date="2016-06-01"),
    person(25, "helen.cho", "Helen", "Cho", "Human Resources", "Access Assurance Auditor", "sofia.berg",
           classification="privileged", join_date="2018-04-23",
           extra_groups=[grant("identity-auditors", "amira.shah", "Independent auditor for access decisions.")]),
    person(26, "nina.vasileva", "Nina", "Vasileva", "Human Resources", "HR Generalist", "sofia.berg", join_date="2022-02-14"),
    person(27, "tomas.reed", "Tomas", "Reed", "Human Resources", "People Operations Partner", "sofia.berg", join_date="2020-07-20"),
    person(28, "lina.ortiz", "Lina", "Ortiz", "Human Resources", "Recruiting Contractor", "sofia.berg",
           employment_type="contractor", classification="contractor", join_date="2025-06-01",
           access_expires_at="2026-01-15T00:00:00Z"),
    person(29, "devon.cho", "Devon", "Cho", "Engineering", "Engineering Manager", None, classification="manager", join_date="2017-03-13"),
    person(30, "noah.petrov", "Noah", "Petrov", "Engineering", "Project Administrator", "devon.cho",
           classification="privileged", join_date="2020-01-08",
           extra_groups=[grant("project-administrators", None, "Assigned during an incident without a recorded approval.", approved=False)]),
    person(31, "hana.iqbal", "Hana", "Iqbal", "Engineering", "Engineering Tools Lead", "devon.cho",
           classification="privileged", join_date="2019-09-02",
           extra_groups=[grant("project-administrators", "amira.shah", "Administers project workspaces and membership.")]),
    person(32, "maya.chen", "Maya", "Chen", "Engineering", "Software Engineer", "devon.cho", join_date="2021-08-16"),
    person(33, "julian.ross", "Julian", "Ross", "Engineering", "Software Engineer", "devon.cho", join_date="2022-10-03"),
    person(34, "aya.nakamura", "Aya", "Nakamura", "Engineering", "Software Engineer", "devon.cho", join_date="2023-04-24"),
    person(35, "erik.solberg", "Erik", "Solberg", "Engineering", "Site Reliability Engineer", "devon.cho", join_date="2018-12-11"),
    person(36, "leila.farouk", "Leila", "Farouk", "Engineering", "Backend Engineer", "devon.cho", join_date="2020-06-29"),
    person(37, "samuel.osei", "Samuel", "Osei", "Engineering", "Frontend Engineer", "devon.cho", join_date="2024-01-15"),
    person(38, "ines.costa", "Ines", "Costa", "Engineering", "QA Engineer", "devon.cho", join_date="2021-05-17"),
    person(39, "haruto.mori", "Haruto", "Mori", "Engineering", "Data Engineer", "devon.cho", join_date="2022-07-07"),
    person(40, "freya.nilsen", "Freya", "Nilsen", "Engineering", "Platform Engineer", "devon.cho", join_date="2019-02-25"),
    person(41, "omar.siddiqui", "Omar", "Siddiqui", "Engineering", "Contract Engineer", "devon.cho",
           employment_type="contractor", classification="contractor", join_date="2026-08-01",
           access_expires_at="2027-02-01T00:00:00Z"),
    person(42, "mina.okada", "Mina", "Okada", "Operations", "Operations Manager", None, classification="manager", join_date="2016-11-08"),
    person(43, "owen.briggs", "Owen", "Briggs", "Operations", "Identity Operations Lead", "mina.okada",
           classification="privileged", join_date="2018-06-18",
           extra_groups=[grant("identity-operators", "amira.shah", "Runs joiner, mover, and leaver workflows.")]),
    person(44, "jonas.keller", "Jonas", "Keller", "Operations", "Facilities Systems Specialist", "mina.okada",
           status="suspended", classification="suspended", join_date="2019-08-12"),
    person(45, "sara.okonkwo", "Sara", "Okonkwo", "Operations", "Logistics Coordinator", "mina.okada",
           status="departed", classification="departed", join_date="2018-03-05", departure_date="2026-09-01"),
    person(46, "paul.meier", "Paul", "Meier", "Operations", "Operations Analyst", "mina.okada", join_date="2023-09-19"),
    person(47, "chioma.eze", "Chioma", "Eze", "Operations", "Service Delivery Lead", "mina.okada", join_date="2021-01-25"),
    person(48, "felix.baum", "Felix", "Baum", "Operations", "Workplace Coordinator", "mina.okada", join_date="2024-11-04"),
    person(49, "svc.finance.batch", "Finance Batch", "Service", "Finance", "Report Batch Service", "david.okeke",
           employment_type="service", classification="service", join_date="2020-01-01",
           extra_groups=[grant("service-accounts", None, "Non-human account.", approved=False),
                         grant("service-finance", None, "Reads finance reports for the nightly batch. No approval on file.", approved=False)]),
    person(50, "svc.projects.sync", "Projects Sync", "Service", "Engineering", "Project Directory Sync", "hana.iqbal",
           employment_type="service", classification="service", join_date="2021-01-01",
           extra_groups=[
               grant("service-accounts", "hana.iqbal", "Non-human account registered to the tools lead."),
               grant("service-projects", "amira.shah", "Reads project membership for directory sync."),
           ]),
]


def main() -> None:
    if len(PEOPLE) != 50:
        raise SystemExit(f"expected 50 identities, found {len(PEOPLE)}")
    usernames = [p["username"] for p in PEOPLE]
    if len(set(usernames)) != 50:
        raise SystemExit("duplicate usernames")
    numbers = [p["employee_number"] for p in PEOPLE]
    if len(set(numbers)) != 50:
        raise SystemExit("duplicate employee numbers")
    known = set(usernames)
    for record in PEOPLE:
        manager = record["manager_username"]
        if manager and manager not in known:
            raise SystemExit(f"unknown manager {manager} for {record['username']}")
    OUT.write_text(json.dumps({"organisation": "Northstar Digital", "people": PEOPLE}, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()

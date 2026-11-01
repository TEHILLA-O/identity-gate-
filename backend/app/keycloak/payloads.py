"""SCIM request bodies for Keycloak's native API. Passwords are never included."""

from __future__ import annotations

CORE = "urn:ietf:params:scim:schemas:core:2.0:User"
ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
REALM_EXT = "urn:keycloak:params:scim:schemas:extension:realm:1.0:User"
PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
ACCESS = "urn:northstar:params:scim:schemas:extension:access:1.0:User"


def user_payload(person: dict, *, manager_id: str | None = None, manager_name: str | None = None, active: bool | None = None) -> dict:
    enabled = person["employment_status"] == "active" if active is None else active
    enterprise = {
        "employeeNumber": person["employee_number"],
        "department": person["department"],
        "costCenter": person["cost_centre"],
        "organization": "Northstar Digital",
    }
    if manager_id:
        enterprise["manager"] = {"value": manager_id, "displayName": manager_name or manager_id}
    realm_ext = {
        "employmentStatus": person["employment_status"],
        "employmentType": person["employment_type"],
        "joinDate": person["join_date"],
        "classification": person["classification"],
    }
    if person.get("departure_date"):
        realm_ext["departureDate"] = person["departure_date"]
    return {
        "schemas": [CORE, ENTERPRISE, REALM_EXT],
        "userName": person["username"],
        "externalId": person["employee_number"],
        "active": enabled,
        "title": person["title"],
        "userType": person["employment_type"],
        "name": {"givenName": person["given_name"], "familyName": person["family_name"]},
        "emails": [{"value": person["email"], "type": "work", "primary": True}],
        ENTERPRISE: enterprise,
        REALM_EXT: realm_ext,
    }


def patch_body(operations: list[dict]) -> dict:
    return {"schemas": [PATCH], "Operations": operations}


def group_payload(name: str) -> dict:
    return {"schemas": [GROUP], "displayName": name, "externalId": name}

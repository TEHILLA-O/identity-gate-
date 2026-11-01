"""Keycloak admin, native SCIM, and downstream SCIM calls.

The master realm administrator is intentionally absent from this module.
Runtime calls use the restricted provisioner service account.
"""

from __future__ import annotations

import time

import httpx

from app.config import Settings, get_settings
from app.keycloak.errors import IntegrationError
from app.keycloak.payloads import ACCESS, patch_body, user_payload
from app.models import ProvisioningAttempt
from app.security.redact import redact
from app.util import new_id, utcnow

MANAGED_CLIENTS = ("northstar-finance", "northstar-projects")


class Gateway:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.http = httpx.Client(timeout=30.0, trust_env=False)
        self._token = ""
        self._token_exp = 0.0
        self._clients: dict[str, str] = {}
        self._groups: dict[str, str] = {}

    def close(self) -> None:
        self.http.close()

    def service_token(self) -> str:
        if self._token and time.time() < self._token_exp - 20:
            return self._token
        response = self.http.post(
            f"{self.settings.internal_realm}/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.settings.scim_client_id,
                "client_secret": self.settings.scim_client_secret,
            },
        )
        if response.status_code != 200:
            raise IntegrationError("Provisioner authentication failed.", retryable=response.status_code >= 500, status=response.status_code)
        body = response.json()
        self._token = body["access_token"]
        self._token_exp = time.time() + int(body.get("expires_in") or 60)
        return self._token

    def _send(self, method: str, url: str, *, headers: dict, body=None, params=None) -> httpx.Response:
        response = self.http.request(method, url, headers=headers, json=body, params=params)
        if response.status_code == 401:
            self._token = ""
            headers = {**headers, "Authorization": f"Bearer {self.service_token()}"}
            response = self.http.request(method, url, headers=headers, json=body, params=params)
        return response

    def _record(self, db, *, correlation_id, target, resource_type, operation, method, path, external_id, response, body, started) -> None:
        if db is None:
            return
        parsed = None
        if response.content:
            try:
                parsed = redact(response.json())
            except Exception:
                parsed = {"text": response.text[:500]}
        message, _retryable = describe(response)
        db.add(
            ProvisioningAttempt(
                id=new_id(),
                correlation_id=correlation_id or "",
                target_system=target,
                resource_type=resource_type,
                operation=operation,
                method=method,
                path=path,
                external_id=external_id,
                resource_id=(parsed or {}).get("id") if isinstance(parsed, dict) else None,
                http_status=response.status_code,
                outcome="success" if response.status_code < 400 else "failed",
                duration_ms=int((time.perf_counter() - started) * 1000),
                request_body=redact(body) if body is not None else None,
                response_body=parsed,
                error_summary=None if response.status_code < 400 else message,
                created_at=utcnow(),
            )
        )
        db.flush()

    def scim(self, method: str, path: str, *, body=None, params=None, db=None, correlation_id="", operation="", external_id="", resource_type="User"):
        started = time.perf_counter()
        headers = {
            "Authorization": f"Bearer {self.service_token()}",
            "Accept": "application/scim+json",
        }
        if body is not None:
            headers["Content-Type"] = "application/scim+json"
        url = self.settings.scim_base + path
        response = self._send(method, url, headers=headers, body=body, params=params)
        self._record(
            db,
            correlation_id=correlation_id,
            target="keycloak-scim",
            resource_type=resource_type,
            operation=operation or method.lower(),
            method=method,
            path=path,
            external_id=external_id,
            response=response,
            body=body,
            started=started,
        )
        return response

    def admin(self, method: str, path: str, *, body=None, params=None, tolerate=()):
        headers = {"Authorization": f"Bearer {self.service_token()}"}
        url = f"{self.settings.keycloak_internal_url.rstrip('/')}/admin/realms/{self.settings.keycloak_realm}{path}"
        response = self._send(method, url, headers=headers, body=body, params=params)
        if response.status_code in tolerate:
            return response
        if response.status_code >= 400:
            message, retryable = describe(response)
            raise IntegrationError(message, retryable=retryable, status=response.status_code)
        return response

    def admin_json(self, method: str, path: str, **kwargs):
        response = self.admin(method, path, **kwargs)
        if not response.content:
            return None
        return response.json()

    def find_user(self, employee_number: str, username: str) -> dict | None:
        for filt in (f'externalId eq "{employee_number}"', f'userName eq "{username}"'):
            response = self.scim("GET", "/Users", params={"filter": filt, "count": 2}, operation="search")
            if response.status_code >= 400:
                continue
            resources = response.json().get("Resources") or []
            if resources:
                return resources[0]
        rows = self.admin_json("GET", "/users", params={"username": username, "exact": "true"}) or []
        if rows:
            return {"id": rows[0]["id"], "userName": rows[0]["username"], "active": rows[0].get("enabled", False)}
        return None

    def upsert_user(self, person: dict, *, manager_id: str | None, manager_name: str | None, active: bool, db, correlation_id: str) -> str:
        payload = user_payload(person, manager_id=manager_id, manager_name=manager_name, active=active)
        existing = self.find_user(person["employee_number"], person["username"])
        if existing:
            user_id = existing["id"]
            response = self.scim(
                "PUT",
                f"/Users/{user_id}",
                body={**payload, "id": user_id},
                db=db,
                correlation_id=correlation_id,
                operation="replace",
                external_id=person["employee_number"],
            )
            if response.status_code == 400:
                slim = {key: value for key, value in payload.items() if not str(key).startswith("urn:keycloak")}
                slim["schemas"] = [item for item in slim["schemas"] if "keycloak" not in item]
                response = self.scim(
                    "PUT",
                    f"/Users/{user_id}",
                    body={**slim, "id": user_id},
                    db=db,
                    correlation_id=correlation_id,
                    operation="replace",
                    external_id=person["employee_number"],
                )
            if response.status_code >= 400:
                self._patch_user(user_id, payload, db, correlation_id, person["employee_number"])
            self._attributes(user_id, person, active, required_actions=None)
            return user_id
        response = self.scim(
            "POST",
            "/Users",
            body=payload,
            db=db,
            correlation_id=correlation_id,
            operation="create",
            external_id=person["employee_number"],
        )
        if response.status_code == 409:
            found = self.find_user(person["employee_number"], person["username"])
            if not found:
                message, retryable = describe(response)
                raise IntegrationError(message, retryable=retryable, status=response.status_code)
            return self.upsert_user(person, manager_id=manager_id, manager_name=manager_name, active=active, db=db, correlation_id=correlation_id)
        if response.status_code >= 400:
            slim = {key: value for key, value in payload.items() if not str(key).startswith("urn:keycloak")}
            slim["schemas"] = [item for item in payload["schemas"] if "keycloak" not in item]
            response = self.scim(
                "POST",
                "/Users",
                body=slim,
                db=db,
                correlation_id=correlation_id,
                operation="create",
                external_id=person["employee_number"],
            )
        if response.status_code >= 400:
            message, retryable = describe(response)
            raise IntegrationError(message, retryable=retryable, status=response.status_code)
        user_id = response.json()["id"]
        self._attributes(user_id, person, active, required_actions=None)
        return user_id

    def _patch_user(self, user_id: str, payload: dict, db, correlation_id: str, external_id: str) -> None:
        operations = [
            {"op": "replace", "path": "active", "value": payload["active"]},
            {"op": "replace", "path": "name.givenName", "value": payload["name"]["givenName"]},
            {"op": "replace", "path": "name.familyName", "value": payload["name"]["familyName"]},
            {"op": "replace", "path": "title", "value": payload.get("title", "")},
        ]
        response = self.scim(
            "PATCH",
            f"/Users/{user_id}",
            body=patch_body(operations),
            db=db,
            correlation_id=correlation_id,
            operation="patch",
            external_id=external_id,
        )
        if response.status_code >= 400:
            message, retryable = describe(response)
            raise IntegrationError(message, retryable=retryable, status=response.status_code)

    def _attributes(self, user_id: str, person: dict, active: bool, required_actions: list[str] | None) -> None:
        user = self.admin_json("GET", f"/users/{user_id}")
        attrs = user.get("attributes") or {}
        attrs.update(
            {
                "employeeNumber": [person["employee_number"]],
                "department": [person["department"]],
                "costCenter": [person["cost_centre"]],
                "employmentStatus": [person["employment_status"]],
                "employmentType": [person["employment_type"]],
                "classification": [person["classification"]],
                "title": [person["title"]],
            }
        )
        user["attributes"] = attrs
        user["emailVerified"] = True
        user["enabled"] = active
        user["firstName"] = person["given_name"]
        user["lastName"] = person["family_name"]
        user["email"] = person["email"]
        if required_actions is not None:
            user["requiredActions"] = required_actions
        self.admin("PUT", f"/users/{user_id}", body=user)

    def set_password(self, user_id: str, password: str, db, correlation_id: str) -> None:
        started = time.perf_counter()
        response = self.admin("PUT", f"/users/{user_id}/reset-password", body={"type": "password", "temporary": False, "value": password})
        self._record(
            db,
            correlation_id=correlation_id,
            target="keycloak-admin",
            resource_type="User",
            operation="set-password",
            method="PUT",
            path=f"/users/{user_id}/reset-password",
            external_id=user_id,
            response=response,
            body={"type": "password", "temporary": False, "value": "[redacted]"},
            started=started,
        )

    def set_required_actions(self, user_id: str, actions: list[str]) -> None:
        user = self.admin_json("GET", f"/users/{user_id}")
        user["requiredActions"] = actions
        self.admin("PUT", f"/users/{user_id}", body=user)

    def group_id(self, name: str) -> str:
        if name not in self._groups:
            groups = self.admin_json("GET", "/groups", params={"search": name, "max": 50}) or []
            for group in groups:
                self._groups[group["name"]] = group["id"]
            if name not in self._groups:
                rows = self.admin_json("GET", "/groups", params={"max": 200}) or []
                for group in rows:
                    self._groups[group["name"]] = group["id"]
        if name not in self._groups:
            raise IntegrationError(f"Keycloak group {name} does not exist.", retryable=False, status=404)
        return self._groups[name]

    def sync_groups(self, user_id: str, desired: list[str], db, correlation_id: str, external_id: str) -> None:
        current = self.admin_json("GET", f"/users/{user_id}/groups") or []
        current_names = {item["name"] for item in current}
        wanted = set(desired)
        for name in sorted(wanted - current_names):
            response = self.scim(
                "PATCH",
                f"/Groups/{self.group_id(name)}",
                body=patch_body([{"op": "add", "path": "members", "value": user_id}]),
                db=db,
                correlation_id=correlation_id,
                operation="add-member",
                external_id=external_id,
                resource_type="Group",
            )
            if response.status_code >= 400:
                message, retryable = describe(response)
                raise IntegrationError(message, retryable=retryable, status=response.status_code)
        for name in sorted(current_names - wanted):
            response = self.scim(
                "PATCH",
                f"/Groups/{self.group_id(name)}",
                body=patch_body([{"op": "remove", "path": f'members[value eq "{user_id}"]'}]),
                db=db,
                correlation_id=correlation_id,
                operation="remove-member",
                external_id=external_id,
                resource_type="Group",
            )
            if response.status_code >= 400:
                message, retryable = describe(response)
                raise IntegrationError(message, retryable=retryable, status=response.status_code)

    def sync_direct_roles(self, user_id: str, desired: list[dict]) -> None:
        wanted = {(item["client"], item["role"]) for item in desired}
        mappings = self.admin_json("GET", f"/users/{user_id}/role-mappings") or {}
        current = {
            (client, role["name"])
            for client, payload in (mappings.get("clientMappings") or {}).items()
            if client in MANAGED_CLIENTS
            for role in payload.get("mappings") or []
        }
        for client, role in sorted(wanted - current):
            rep = self.admin_json("GET", f"/clients/{self.client_uuid(client)}/roles/{role}")
            self.admin(
                "POST",
                f"/users/{user_id}/role-mappings/clients/{self.client_uuid(client)}",
                body=[{"id": rep["id"], "name": rep["name"]}],
            )
        for client, role in sorted(current - wanted):
            rep = self.admin_json("GET", f"/clients/{self.client_uuid(client)}/roles/{role}")
            self.admin(
                "DELETE",
                f"/users/{user_id}/role-mappings/clients/{self.client_uuid(client)}",
                body=[{"id": rep["id"], "name": rep["name"]}],
            )

    def client_uuid(self, client_id: str) -> str:
        if client_id not in self._clients:
            rows = self.admin_json("GET", "/clients", params={"clientId": client_id}) or []
            if not rows:
                raise IntegrationError(f"Client {client_id} was not found.", retryable=False, status=404)
            self._clients[client_id] = rows[0]["id"]
        return self._clients[client_id]

    def logout(self, user_id: str) -> None:
        self.admin("POST", f"/users/{user_id}/logout", tolerate=(204,))

    def observe(self, user_id: str) -> dict:
        user = self.admin_json("GET", f"/users/{user_id}")
        groups = self.admin_json("GET", f"/users/{user_id}/groups") or []
        mappings = self.admin_json("GET", f"/users/{user_id}/role-mappings") or {}
        realm_effective = self.admin_json("GET", f"/users/{user_id}/role-mappings/realm/composite") or []
        credentials = self.admin_json("GET", f"/users/{user_id}/credentials") or []
        sessions = self.admin_json("GET", f"/users/{user_id}/sessions") or []
        direct_client = {
            client: [item["name"] for item in payload.get("mappings") or []]
            for client, payload in (mappings.get("clientMappings") or {}).items()
        }
        effective_client = {}
        for client, payload in (mappings.get("clientMappings") or {}).items():
            client_uuid = payload.get("id")
            if not client_uuid:
                effective_client[client] = direct_client.get(client, [])
                continue
            composite = self.admin_json("GET", f"/users/{user_id}/role-mappings/clients/{client_uuid}/composite") or []
            effective_client[client] = [item["name"] for item in composite]
        for client in MANAGED_CLIENTS:
            effective_client.setdefault(client, [])
            uuid = self.client_uuid(client)
            composite = self.admin_json("GET", f"/users/{user_id}/role-mappings/clients/{uuid}/composite") or []
            effective_client[client] = sorted({*effective_client.get(client, []), *(item["name"] for item in composite)})
        return {
            "enabled": bool(user.get("enabled")),
            "groups": sorted(item["name"] for item in groups),
            "direct_client_roles": direct_client,
            "direct_realm_roles": [item["name"] for item in mappings.get("realmMappings") or []],
            "effective_client_roles": effective_client,
            "effective_realm_roles": [item["name"] for item in realm_effective],
            "mfa_enrolled": any(item.get("type") == "otp" for item in credentials),
            "session_count": len(sessions),
        }

    def downstream_upsert(self, desired: dict, db, correlation_id: str) -> dict:
        return downstream_call(self, "upsert", desired, db, correlation_id)

    def downstream_list(self) -> list[dict]:
        return downstream_call(self, "list", None, None, "")

    def events(self, first: int = 0) -> list[dict]:
        return self.admin_json("GET", "/events", params={"first": first, "max": 100}) or []

    def admin_events(self, first: int = 0) -> list[dict]:
        return self.admin_json("GET", "/admin-events", params={"first": first, "max": 100}) or []

    def client_redirects(self) -> list[dict]:
        rows = []
        for client_id in ("identitygate", "northstar-finance", "northstar-projects", "identitygate-provisioner"):
            found = self.admin_json("GET", "/clients", params={"clientId": client_id}) or []
            if not found:
                continue
            rows.append({"client": client_id, "uris": found[0].get("redirectUris") or []})
        return rows

    def realm_settings(self) -> dict:
        realm = self.admin_json("GET", "")
        return {
            "eventsEnabled": realm.get("eventsEnabled"),
            "adminEventsEnabled": realm.get("adminEventsEnabled"),
            "scimApiEnabled": realm.get("scimApiEnabled"),
        }


def describe(response: httpx.Response) -> tuple[str, bool]:
    retryable = response.status_code in {408, 429, 500, 502, 503, 504}
    detail = ""
    try:
        body = response.json()
    except Exception:
        body = None
    if isinstance(body, dict):
        detail = str(body.get("errorMessage") or body.get("detail") or body.get("scimType") or body.get("error") or "")
    message = f"HTTP {response.status_code} {detail}".strip()[:400]
    return message, retryable


def downstream_call(gateway: Gateway, action: str, desired: dict | None, db, correlation_id: str):
    base = gateway.settings.downstream_scim_url.rstrip("/")
    token = gateway.settings.downstream_scim_token
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/scim+json", "Content-Type": "application/scim+json"}

    def send(method, path, body=None, params=None):
        started = time.perf_counter()
        try:
            response = gateway.http.request(method, base + path, headers=headers, json=body, params=params)
        except httpx.HTTPError as exc:
            raise IntegrationError("Downstream directory was unreachable.", retryable=True) from exc
        gateway._record(
            db,
            correlation_id=correlation_id,
            target="northstar-directory",
            resource_type="User" if "/Groups" not in path else "Group",
            operation=action,
            method=method,
            path=path,
            external_id=(desired or {}).get("externalId", ""),
            response=response,
            body=body,
            started=started,
        )
        if response.status_code >= 400 and response.status_code not in {404, 409}:
            message, retryable = describe(response)
            raise IntegrationError(message, retryable=retryable or response.status_code == 404, status=response.status_code)
        return response

    if action == "list":
        items = []
        start = 1
        while True:
            response = send("GET", "/Users", params={"startIndex": start, "count": 100})
            body = response.json()
            resources = body.get("Resources") or []
            items.extend(resources)
            total = body.get("totalResults", 0)
            if not resources or len(items) >= total:
                break
            start += len(resources)
        return items

    assert desired is not None
    filt = f'externalId eq "{desired["externalId"]}"'
    found = send("GET", "/Users", params={"filter": filt, "count": 2})
    resources = found.json().get("Resources") or []
    body = {
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:User",
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
            ACCESS,
        ],
        "userName": desired["userName"],
        "externalId": desired["externalId"],
        "active": desired["active"],
        "name": desired["name"],
        "emails": desired["emails"],
        "title": desired.get("title"),
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"department": desired.get("department"), "employeeNumber": desired["externalId"]},
        ACCESS: {"roles": desired.get("roles") or []},
    }
    if resources:
        user_id = resources[0]["id"]
        send("PUT", f"/Users/{user_id}", body={**body, "id": user_id})
    else:
        created = send("POST", "/Users", body=body)
        if created.status_code == 409:
            return downstream_call(gateway, action, desired, db, correlation_id)
        user_id = created.json()["id"]
    for group_name in desired.get("groups") or []:
        group_id = ensure_downstream_group(send, group_name)
        current = send("GET", f"/Groups/{group_id}", params={"attributes": "members"}).json()
        members = {item.get("value") for item in current.get("members") or []}
        if user_id not in members:
            send("PATCH", f"/Groups/{group_id}", body=patch_body([{"op": "add", "path": "members", "value": user_id}]))
    existing_groups = send("GET", "/Groups", params={"filter": f'members.value eq "{user_id}"', "count": 100}).json()
    for group in existing_groups.get("Resources") or []:
        if group.get("displayName") not in set(desired.get("groups") or []):
            send("PATCH", f"/Groups/{group['id']}", body=patch_body([{"op": "remove", "path": f'members[value eq "{user_id}"]'}]))
    return {"id": user_id, "active": desired["active"]}


def ensure_downstream_group(send, name: str) -> str:
    found = send("GET", "/Groups", params={"filter": f'displayName eq "{name}"', "count": 2}).json()
    resources = found.get("Resources") or []
    if resources:
        return resources[0]["id"]
    created = send("POST", "/Groups", body={"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": name, "externalId": name})
    if created.status_code == 409:
        return ensure_downstream_group(send, name)
    return created.json()["id"]

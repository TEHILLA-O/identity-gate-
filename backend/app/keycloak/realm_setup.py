"""Realm bootstrap using the temporary master admin, then the restricted service account."""

from __future__ import annotations

import time

import httpx
import jwt
from policy.decision import load_catalog

from app.config import Settings
from app.keycloak.errors import IntegrationError

PROVISIONER_ROLES = [
    "manage-users",
    "view-users",
    "query-users",
    "query-groups",
    "view-events",
    "view-clients",
    "query-clients",
    "view-realm",
]

SCIM_ATTRIBUTES = {
    "externalId": "externalId",
    "title": "title",
    "userType": "userType",
    "employeeNumber": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber",
    "department": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
    "costCenter": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:costCenter",
    "organization": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:organization",
    "manager": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value",
    "managerName": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.displayName",
    "employmentStatus": "urn:keycloak:params:scim:schemas:extension:realm:1.0:User:employmentStatus",
    "employmentType": "urn:keycloak:params:scim:schemas:extension:realm:1.0:User:employmentType",
    "joinDate": "urn:keycloak:params:scim:schemas:extension:realm:1.0:User:joinDate",
    "departureDate": "urn:keycloak:params:scim:schemas:extension:realm:1.0:User:departureDate",
    "classification": "urn:keycloak:params:scim:schemas:extension:realm:1.0:User:classification",
}


def _claim(name: str, attribute: str, claim: str) -> dict:
    return {
        "name": name,
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-property-mapper",
        "config": {
            "user.attribute": attribute,
            "claim.name": claim,
            "jsonType.label": "String",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
        },
    }


_SCOPE_MAPPERS = {
    "profile": [
        _claim("username", "username", "preferred_username"),
        _claim("given name", "firstName", "given_name"),
        _claim("family name", "lastName", "family_name"),
        {"name": "full name", "protocol": "openid-connect", "protocolMapper": "oidc-full-name-mapper", "config": {"id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true"}},
    ],
    "email": [
        _claim("email", "email", "email"),
        _claim("email verified", "emailVerified", "email_verified"),
    ],
    "roles": [
        {"name": "realm roles", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-realm-role-mapper", "config": {"claim.name": "realm_access.roles", "jsonType.label": "String", "multivalued": "true", "id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true"}},
        {"name": "client roles", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-client-role-mapper", "config": {"claim.name": "resource_access.${client_id}.roles", "jsonType.label": "String", "multivalued": "true", "id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true"}},
        {"name": "audience resolve", "protocol": "openid-connect", "protocolMapper": "oidc-audience-resolve-mapper", "config": {"access.token.claim": "true", "introspection.token.claim": "true"}},
    ],
    "web-origins": [
        {"name": "allowed web origins", "protocol": "openid-connect", "protocolMapper": "oidc-allowed-origins-mapper", "config": {"access.token.claim": "true", "introspection.token.claim": "true"}},
    ],
    "acr": [
        {"name": "acr loa level", "protocol": "openid-connect", "protocolMapper": "oidc-acr-mapper", "config": {"id.token.claim": "true", "access.token.claim": "true"}},
    ],
}


class RealmSetup:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.http = httpx.Client(timeout=30.0, trust_env=False)
        self.token = ""

    def close(self) -> None:
        self.http.close()

    def wait(self, attempts: int = 60) -> None:
        url = f"{self.settings.keycloak_internal_url.rstrip('/')}/realms/master"
        for _ in range(attempts):
            try:
                response = self.http.get(url)
                if response.status_code < 500:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(3)
        raise IntegrationError("Keycloak did not become ready.", retryable=True)

    def authenticate(self) -> None:
        response = self.http.post(
            f"{self.settings.keycloak_internal_url.rstrip('/')}/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": self.settings.kc_admin_username,
                "password": self.settings.kc_admin_password,
            },
        )
        if response.status_code != 200:
            raise IntegrationError("Master administrator login failed.", retryable=True, status=response.status_code)
        self.token = response.json()["access_token"]

    def request(self, method: str, path: str, *, tolerate: tuple[int, ...] = (), **kwargs) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self.token}"}
        url = f"{self.settings.keycloak_internal_url.rstrip('/')}/admin/realms/{self.settings.keycloak_realm}{path}"
        response = self.http.request(method, url, headers=headers, **kwargs)
        if response.status_code in tolerate:
            return response
        if response.status_code >= 400:
            raise IntegrationError(f"Realm setup failed on {method} {path}: HTTP {response.status_code} {response.text[:240]}", retryable=response.status_code >= 500, status=response.status_code)
        return response

    def configure(self) -> None:
        self._builtin_scopes()
        self._secrets()
        self._service_account()
        self._profile()
        self._group_roles()
        self._scim_flag()
        self._audience()

    def _builtin_scopes(self) -> None:
        """The realm import runs before Keycloak's built-in scopes exist, so attach them here."""
        existing = {row["name"]: row["id"] for row in self.request("GET", "/client-scopes").json()}
        for name, mappers in _SCOPE_MAPPERS.items():
            if name not in existing:
                created = self.request("POST", "/client-scopes", json={"name": name, "protocol": "openid-connect", "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "false"}})
                existing[name] = created.headers.get("location", "").rstrip("/").split("/")[-1]
            scope_id = existing[name]
            present = {row["name"] for row in self.request("GET", f"/client-scopes/{scope_id}/protocol-mappers/models").json()}
            for mapper in mappers:
                if mapper["name"] not in present:
                    self.request("POST", f"/client-scopes/{scope_id}/protocol-mappers/models", json=mapper)
        for client_id in ("identitygate", "northstar-finance", "northstar-projects", "identitygate-provisioner"):
            client = self._client(client_id)
            assigned = {row["name"] for row in self.request("GET", f"/clients/{client['id']}/default-client-scopes").json()}
            for name, scope_id in existing.items():
                if name in _SCOPE_MAPPERS and name not in assigned:
                    self.request("PUT", f"/clients/{client['id']}/default-client-scopes/{scope_id}")

    def _client(self, client_id: str) -> dict:
        rows = self.request("GET", "/clients", params={"clientId": client_id}).json()
        if not rows:
            raise IntegrationError(f"Client {client_id} is missing from the realm.", retryable=False)
        return rows[0]

    def _secrets(self) -> None:
        secrets = {
            "identitygate": self.settings.oidc_client_secret,
            "northstar-finance": self.settings.finance_client_secret,
            "northstar-projects": self.settings.projects_client_secret,
            "identitygate-provisioner": self.settings.scim_client_secret,
        }
        for client_id, secret in secrets.items():
            client = self._client(client_id)
            client["secret"] = secret
            if client_id == "identitygate-provisioner":
                client["fullScopeAllowed"] = False
                client["standardFlowEnabled"] = False
                client["directAccessGrantsEnabled"] = False
            else:
                client["fullScopeAllowed"] = True
            self.request("PUT", f"/clients/{client['id']}", json=client)

    def _service_account(self) -> None:
        client = self._client("identitygate-provisioner")
        realm_mgmt = self._client("realm-management")
        account = self.request("GET", f"/clients/{client['id']}/service-account-user").json()
        roles = []
        for name in PROVISIONER_ROLES:
            try:
                roles.append(self.request("GET", f"/clients/{realm_mgmt['id']}/roles/{name}").json())
            except IntegrationError:
                continue
        if not any(role["name"] == "manage-users" for role in roles):
            raise IntegrationError("manage-users is not available for the provisioner.", retryable=False)
        self.request("POST", f"/users/{account['id']}/role-mappings/clients/{realm_mgmt['id']}", json=roles, tolerate=(409,))
        self.request("POST", f"/clients/{client['id']}/scope-mappings/clients/{realm_mgmt['id']}", json=roles, tolerate=(409,))

    def _profile(self) -> None:
        profile = self.request("GET", "/users/profile").json()
        attributes = {item["name"]: item for item in profile.get("attributes") or []}
        for name, scim_name in SCIM_ATTRIBUTES.items():
            current = attributes.get(name, {"name": name, "displayName": name, "permissions": {"view": ["admin"], "edit": ["admin"]}})
            annotations = dict(current.get("annotations") or {})
            annotations["kc.scim.schema.attribute"] = scim_name
            current["annotations"] = annotations
            current["permissions"] = current.get("permissions") or {"view": ["admin"], "edit": ["admin"]}
            attributes[name] = current
        profile["attributes"] = list(attributes.values())
        profile["unmanagedAttributePolicy"] = profile.get("unmanagedAttributePolicy") or "ADMIN_EDIT"
        self.request("PUT", "/users/profile", json=profile)

    def _group_roles(self) -> None:
        catalog = load_catalog()
        groups = self.request("GET", "/groups", params={"max": 200}).json()
        by_name = {group["name"]: group["id"] for group in groups}
        realm_roles = {role["name"]: role for role in self.request("GET", "/roles").json()}
        clients = {item["clientId"]: item["id"] for item in self.request("GET", "/clients").json()}
        for name, binding in catalog["groups"].items():
            group_id = by_name.get(name)
            if not group_id:
                created = self.request("POST", "/groups", json={"name": name})
                location = created.headers.get("location", "")
                group_id = location.rstrip("/").split("/")[-1]
            realm_payload = [realm_roles[role] for role in binding["realm"] if role in realm_roles]
            if realm_payload:
                self.request("POST", f"/groups/{group_id}/role-mappings/realm", json=[{"id": role["id"], "name": role["name"]} for role in realm_payload], tolerate=(409,))
            for client_id, roles in binding["clients"].items():
                client_uuid = clients[client_id]
                payload = []
                for role_name in roles:
                    role = self.request("GET", f"/clients/{client_uuid}/roles/{role_name}").json()
                    payload.append({"id": role["id"], "name": role["name"]})
                if payload:
                    self.request("POST", f"/groups/{group_id}/role-mappings/clients/{client_uuid}", json=payload, tolerate=(409,))

    def _scim_flag(self) -> None:
        realm = self.request("GET", "").json()
        if realm.get("scimApiEnabled") and realm.get("eventsEnabled") and realm.get("adminEventsEnabled"):
            return
        realm["scimApiEnabled"] = True
        realm["eventsEnabled"] = True
        realm["adminEventsEnabled"] = True
        realm["adminEventsDetailsEnabled"] = True
        self.request("PUT", "", json=realm)

    def _audience(self) -> None:
        client = self._client("identitygate-provisioner")
        audiences = {
            self.settings.scim_audience,
            f"{self.settings.keycloak_internal_url.rstrip('/')}/realms/{self.settings.keycloak_realm}/scim/v2",
        }
        existing = self.request("GET", f"/clients/{client['id']}/protocol-mappers/models").json()
        present = {mapper.get("config", {}).get("included.custom.audience") for mapper in existing}
        for index, audience in enumerate(sorted(audiences)):
            if audience in present:
                continue
            self.request(
                "POST",
                f"/clients/{client['id']}/protocol-mappers/models",
                json={
                    "name": f"scim-audience-{index}",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "config": {
                        "included.custom.audience": audience,
                        "access.token.claim": "true",
                        "id.token.claim": "false",
                        "introspection.token.claim": "true",
                    },
                },
            )
        token = self._service_token()
        claims = jwt.decode(token, options={"verify_signature": False})
        audience = claims.get("aud")
        values = audience if isinstance(audience, list) else [audience]
        if self.settings.scim_audience not in values and not any(str(item).endswith("/scim/v2") for item in values):
            raise IntegrationError("Provisioner token is missing the SCIM audience.", retryable=False)

    def _service_token(self) -> str:
        response = self.http.post(
            f"{self.settings.internal_realm}/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.settings.scim_client_id,
                "client_secret": self.settings.scim_client_secret,
            },
        )
        if response.status_code != 200:
            raise IntegrationError("Provisioner client credentials were rejected.", retryable=True, status=response.status_code)
        return response.json()["access_token"]

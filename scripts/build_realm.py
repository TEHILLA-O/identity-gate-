"""Build the Northstar realm import for Keycloak 26.8."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = json.loads((ROOT / "data" / "access_catalog.json").read_text(encoding="utf-8"))
OUT = ROOT / "keycloak" / "realm-config" / "northstar-realm.json"

SCIM_AUDIENCE = "http://localhost:8080/realms/northstar/scim/v2"


def client(
    client_id: str,
    name: str,
    secret_env: str,
    root: str,
    redirects: list[str],
    origins: list[str],
    *,
    service_account: bool = False,
    standard_flow: bool = True,
    full_scope: bool = True,
    mappers: list | None = None,
) -> dict:
    return {
        "clientId": client_id,
        "name": name,
        "description": name,
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "secret": secret_env,
        "serviceAccountsEnabled": service_account,
        "standardFlowEnabled": standard_flow,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "frontchannelLogout": True,
        "fullScopeAllowed": full_scope,
        "rootUrl": root,
        "baseUrl": root,
        "redirectUris": redirects,
        "webOrigins": origins,
        "attributes": {
            "pkce.code.challenge.method": "S256",
            "post.logout.redirect.uris": "##".join(origins) if origins else "+",
            "oauth2.device.authorization.grant.enabled": "false",
        },
        "defaultClientScopes": ["roles", "profile", "email", "web-origins", "acr"],
        "optionalClientScopes": ["offline_access"],
        "protocolMappers": mappers or [],
    }


def audience(name: str, value: str) -> dict:
    return {
        "name": name,
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "consentRequired": False,
        "config": {
            "included.custom.audience": value,
            "access.token.claim": "true",
            "id.token.claim": "false",
            "introspection.token.claim": "true",
            "userinfo.token.claim": "false",
        },
    }


def role(name: str, description: str) -> dict:
    return {"name": name, "description": description, "composite": False, "clientRole": False}


def main() -> None:
    groups = []
    for name, binding in CATALOG["groups"].items():
        groups.append(
            {
                "name": name,
                "attributes": {"externalId": [name]},
                "realmRoles": binding["realm"],
                "clientRoles": binding["clients"],
            }
        )
    client_roles = {
        client_id: [{"name": role_name, "description": role_name.replace("-", " "), "clientRole": True, "composite": False} for role_name in roles]
        for client_id, roles in CATALOG["clients"].items()
    }

    realm = {
        "realm": "northstar",
        "displayName": "Northstar Digital",
        "enabled": True,
        "sslRequired": "none",
        "registrationAllowed": False,
        "loginWithEmailAllowed": True,
        "duplicateEmailsAllowed": False,
        "resetPasswordAllowed": False,
        "editUsernameAllowed": False,
        "bruteForceProtected": True,
        "permanentLockout": False,
        "failureFactor": 30,
        "waitIncrementSeconds": 60,
        "maxFailureWaitSeconds": 900,
        "minimumQuickLoginWaitSeconds": 60,
        "quickLoginCheckMilliSeconds": 1000,
        "maxDeltaTimeSeconds": 43200,
        "accessTokenLifespan": 300,
        "accessTokenLifespanForImplicitFlow": 300,
        "ssoSessionIdleTimeout": 1800,
        "ssoSessionMaxLifespan": 36000,
        "revokeRefreshToken": True,
        "refreshTokenMaxReuse": 0,
        "eventsEnabled": True,
        "eventsExpiration": 2592000,
        "adminEventsEnabled": True,
        "adminEventsDetailsEnabled": True,
        "eventsListeners": ["jboss-logging"],
        "enabledEventTypes": [
            "LOGIN",
            "LOGIN_ERROR",
            "LOGOUT",
            "LOGOUT_ERROR",
            "CODE_TO_TOKEN",
            "CODE_TO_TOKEN_ERROR",
            "REFRESH_TOKEN",
            "REFRESH_TOKEN_ERROR",
            "REGISTER",
            "REGISTER_ERROR",
            "UPDATE_PASSWORD",
            "VERIFY_EMAIL",
            "CLIENT_LOGIN",
            "CLIENT_LOGIN_ERROR",
        ],
        "internationalizationEnabled": False,
        "scimApiEnabled": True,
        "otpPolicyType": "totp",
        "otpPolicyAlgorithm": "HmacSHA1",
        "otpPolicyDigits": 6,
        "otpPolicyPeriod": 30,
        "passwordPolicy": "length(12) and notUsername",
        "roles": {
            "realm": [role(name, name.replace("-", " ")) for name in CATALOG["realm_roles"]],
            "client": client_roles,
        },
        "groups": groups,
        "clients": [
            client(
                "identitygate",
                "IdentityGate",
                "${IDENTITYGATE_CLIENT_SECRET}",
                "http://localhost:5173",
                ["http://localhost:5173/api/v1/auth/callback"],
                ["http://localhost:5173"],
                mappers=[audience("identitygate-api-audience", "identitygate-api")],
            ),
            client(
                "northstar-finance",
                "Northstar Finance",
                "${FINANCE_CLIENT_SECRET}",
                "http://localhost:8101",
                ["http://localhost:8101/auth/callback"],
                ["http://localhost:8101"],
                mappers=[audience("finance-audience", "northstar-finance")],
            ),
            client(
                "northstar-projects",
                "Northstar Projects",
                "${PROJECTS_CLIENT_SECRET}",
                "http://localhost:8102",
                ["http://localhost:8102/auth/callback"],
                ["http://localhost:8102"],
                mappers=[audience("projects-audience", "northstar-projects")],
            ),
            client(
                "identitygate-provisioner",
                "IdentityGate Provisioner",
                "${SCIM_CLIENT_SECRET}",
                "",
                [],
                [],
                service_account=True,
                standard_flow=False,
                full_scope=False,
                mappers=[audience("scim-audience", SCIM_AUDIENCE)],
            ),
        ],
        "clientScopes": [],
    }
    for entry in realm["clients"]:
        if entry["clientId"] != "identitygate-provisioner":
            continue
        entry["defaultClientScopes"] = ["roles"]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(realm, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()

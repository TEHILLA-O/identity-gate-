"""Segregation-of-duties evaluation against effective access."""

from __future__ import annotations

from datetime import datetime, timezone


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def effective_permissions(matrix: dict, application: str, roles: set[str]) -> set[str]:
    app = matrix["applications"].get(application)
    if not app:
        return set()
    return {action for action, holders in app["actions"].items() if set(holders) & roles}


def _has_role(spec: dict, client_roles: dict[str, set[str]], realm_roles: set[str]) -> bool:
    if spec["application"] == "realm":
        return spec["role"] in realm_roles
    return spec["role"] in client_roles.get(spec["application"], set())


def _has_permission(spec: dict, permissions: dict[str, set[str]]) -> bool:
    return spec["permission"] in permissions.get(spec["application"], set())


def active_exception(exceptions: list[dict], rule_id: str, subject: str, now: datetime) -> dict | None:
    for item in exceptions:
        if item.get("rule_id") != rule_id or item.get("subject") != subject:
            continue
        if item.get("state") not in {"active", "approved"}:
            continue
        expiry = _parse(item.get("expires_at"))
        if expiry and expiry <= now:
            continue
        return item
    return None


def evaluate(
    matrix: dict,
    client_roles: dict[str, set[str] | list[str]],
    realm_roles: set[str] | list[str],
    *,
    subject: str,
    exceptions: list[dict] | None = None,
    now: datetime | None = None,
) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    clients = {app: set(roles) for app, roles in client_roles.items()}
    realm = set(realm_roles)
    permissions = {app: effective_permissions(matrix, app, roles) for app, roles in clients.items()}
    found = []
    for rule in matrix["sod"]:
        if rule.get("kind") == "permission":
            conflicted = _has_permission(rule["left"], permissions) and _has_permission(rule["right"], permissions)
        else:
            conflicted = _has_role(rule["left"], clients, realm) and _has_role(rule["right"], clients, realm)
        if not conflicted:
            continue
        exception = active_exception(exceptions or [], rule["id"], subject, now)
        found.append(
            {
                "rule_id": rule["id"],
                "version": rule["version"],
                "severity": rule["severity"],
                "scope": rule["scope"],
                "explanation": rule["explanation"],
                "subject": subject,
                "status": "excepted" if exception else "open",
                "exception": exception,
                "left": rule["left"],
                "right": rule["right"],
            }
        )
    return found

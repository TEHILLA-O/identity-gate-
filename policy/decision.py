"""Authorisation decisions shared by IdentityGate and the sample applications."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = Path(__file__).resolve().parents[1] / "data" / "permission_matrix.json"


def load_matrix(path: Path | None = None) -> dict:
    return json.loads((path or MATRIX_PATH).read_text(encoding="utf-8"))


def load_catalog(path: Path | None = None) -> dict:
    catalog = path or (ROOT / "data" / "access_catalog.json")
    return json.loads(catalog.read_text(encoding="utf-8"))


def roles_granting(matrix: dict, application: str, action: str) -> set[str]:
    try:
        return set(matrix["applications"][application]["actions"][action])
    except KeyError as exc:
        raise KeyError(f"unknown action {application}:{action}") from exc


def is_allowed(matrix: dict, application: str, action: str, roles: set[str] | list[str]) -> bool:
    held = set(roles)
    return bool(held & roles_granting(matrix, application, action))


def decision(matrix: dict, application: str, action: str, roles: set[str] | list[str]) -> dict:
    held = sorted(set(roles))
    required = sorted(roles_granting(matrix, application, action))
    allowed = bool(set(held) & set(required))
    if allowed:
        reason = f"Allowed because the effective roles include {sorted(set(held) & set(required))}."
    else:
        reason = (
            f"Denied. The account holds [{', '.join(held) or 'no application roles'}] "
            f"and {action} requires one of [{', '.join(required)}]."
        )
    return {
        "application": application,
        "action": action,
        "allowed": allowed,
        "effective_roles": held,
        "required_roles": required,
        "reason": reason,
        "policy_version": matrix["version"],
    }

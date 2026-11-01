"""Effective access paths and entitlement diffs.

Paths are explanations. Allow or deny decisions use effective roles via policy.decision
so the explanation cannot grant more than the identity provider reports.
"""

from __future__ import annotations

from policy.decision import load_catalog, load_matrix

IGNORED_REALM_ROLES = {"offline_access", "uma_authorization"}


def _ignored(role: str) -> bool:
    return role in IGNORED_REALM_ROLES or role.startswith("default-roles-")


def permissions_for(matrix: dict, application: str, role: str) -> list[str]:
    app = matrix["applications"].get(application)
    if not app:
        return []
    return [action for action, holders in app["actions"].items() if role in holders]


def birthright_groups(person: dict, catalog: dict | None = None) -> list[str]:
    catalog = catalog or load_catalog()
    groups = list(catalog["birthright_groups"])
    if person["employment_type"] == "service":
        return ["service-accounts"]
    department = catalog["department_groups"].get(person["department"])
    if department:
        groups.append(department)
    if person["employment_type"] == "contractor":
        groups.append("contractors")
    return _unique(groups)


def desired_groups(person: dict, catalog: dict | None = None) -> list[str]:
    catalog = catalog or load_catalog()
    groups = birthright_groups(person, catalog)
    for grant in person.get("extra_groups") or []:
        groups.append(grant["group"])
    return _unique(groups)


def groups_after_move(person: dict, new_department: str, catalog: dict | None = None) -> list[str]:
    """Recompute birthright and keep only identity-governance extras.

    Application extras from the previous department are not carried forward.
    Privileged access has to be requested again.
    """

    catalog = catalog or load_catalog()
    moved = {**person, "department": new_department}
    groups = birthright_groups(moved, catalog)
    for grant in person.get("extra_groups") or []:
        if grant["group"].startswith("identity-"):
            groups.append(grant["group"])
    return _unique(groups)


def _unique(items: list[str]) -> list[str]:
    seen: list[str] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


def roles_from_groups(groups: list[str], catalog: dict) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for group in groups:
        binding = catalog["groups"].get(group) or {"realm": [], "clients": {}}
        for role in binding.get("realm") or []:
            found.setdefault("realm", set()).add(role)
        for app, roles in (binding.get("clients") or {}).items():
            found.setdefault(app, set()).update(roles)
    return found


def access_paths(
    groups: list[str],
    direct_client: dict[str, list[str]],
    direct_realm: list[str],
    effective_client: dict[str, list[str]] | None = None,
    effective_realm: list[str] | None = None,
    catalog: dict | None = None,
    matrix: dict | None = None,
) -> list[dict]:
    catalog = catalog or load_catalog()
    matrix = matrix or load_matrix()
    privileged = set(matrix["privileged_roles"])
    paths: list[dict] = []

    def add(source: str, group: str | None, application: str, role: str) -> None:
        perms = permissions_for(matrix, application, role) if application != "realm" else []
        base = {
            "source": source,
            "group": group,
            "application": application,
            "role": role,
            "privileged": role in privileged,
        }
        if not perms:
            paths.append({**base, "permission": None})
            return
        for perm in perms:
            paths.append({**base, "permission": perm})

    for group in groups:
        binding = catalog["groups"].get(group) or {"realm": [], "clients": {}}
        for role in binding.get("realm") or []:
            if not _ignored(role):
                add("group", group, "realm", role)
        for app, roles in (binding.get("clients") or {}).items():
            for role in roles:
                add("group", group, app, role)
    for role in direct_realm:
        if not _ignored(role):
            add("direct", None, "realm", role)
    for app, roles in direct_client.items():
        for role in roles:
            add("direct", None, app, role)

    explained = {(item["application"], item["role"]) for item in paths}
    for app, roles in (effective_client or {}).items():
        for role in roles:
            if (app, role) not in explained:
                add("unresolved", None, app, role)
    for role in effective_realm or []:
        if not _ignored(role) and ("realm", role) not in explained:
            add("unresolved", None, "realm", role)
    return paths


def summarise(paths: list[dict]) -> dict:
    permissions = []
    seen = set()
    for path in paths:
        if not path["permission"]:
            continue
        key = (path["application"], path["permission"])
        if key in seen:
            continue
        seen.add(key)
        contributors = [
            p for p in paths if p["application"] == key[0] and p["permission"] == key[1]
        ]
        permissions.append(
            {
                "application": key[0],
                "permission": key[1],
                "privileged": any(p["privileged"] for p in contributors),
                "paths": contributors,
            }
        )
    return {"permissions": permissions, "paths": paths}


def diff_assignments(
    before_groups: list[str],
    after_groups: list[str],
    before_direct: dict[str, list[str]],
    after_direct: dict[str, list[str]],
    catalog: dict | None = None,
) -> dict:
    catalog = catalog or load_catalog()

    def pack(groups: list[str], direct: dict[str, list[str]]) -> set[tuple[str, str]]:
        roles = set()
        grouped = roles_from_groups(groups, catalog)
        for app, held in grouped.items():
            for role in held:
                roles.add((app, role))
        for app, held in direct.items():
            for role in held:
                roles.add((app, role))
        return roles

    before = pack(before_groups, before_direct)
    after = pack(after_groups, after_direct)
    return {
        "removed": [{"application": app, "role": role} for app, role in sorted(before - after)],
        "added": [{"application": app, "role": role} for app, role in sorted(after - before)],
        "unchanged": [{"application": app, "role": role} for app, role in sorted(before & after)],
        "removed_groups": sorted(set(before_groups) - set(after_groups)),
        "added_groups": sorted(set(after_groups) - set(before_groups)),
    }


def compare_paths(left: list[dict], right: list[dict]) -> dict:
    def perms(paths: list[dict]) -> set[tuple[str, str]]:
        return {(p["application"], p["permission"]) for p in paths if p["permission"]}

    left_p, right_p = perms(left), perms(right)
    def pack(items: set[tuple[str, str]], paths: list[dict]) -> list[dict]:
        packed = []
        for app, perm in sorted(items):
            privileged = any(p["privileged"] for p in paths if p["application"] == app and p["permission"] == perm)
            packed.append({"application": app, "permission": perm, "privileged": privileged})
        return packed

    return {
        "shared": pack(left_p & right_p, left),
        "left_only": pack(left_p - right_p, left),
        "right_only": pack(right_p - left_p, right),
    }

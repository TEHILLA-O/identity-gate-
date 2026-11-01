"""Server-side approval plans. Callers cannot choose the approver."""

from __future__ import annotations


class Unassignable(Exception):
    pass


def approval_plan(
    *,
    target: str,
    requester: str,
    manager: str | None,
    role: str,
    privileged_roles: set[str],
    security_reviewer: str,
    independent_reviewer: str,
) -> list[dict]:
    privileged = role in privileged_roles
    blocked = {target, requester}
    steps: list[dict] = []
    if manager and manager not in blocked:
        steps.append({"kind": "manager", "username": manager, "status": "pending"})
    if privileged or not steps:
        reviewer = security_reviewer if security_reviewer not in blocked else independent_reviewer
        if reviewer in blocked:
            raise Unassignable("No independent approver is available for this request.")
        if not any(step["username"] == reviewer for step in steps):
            steps.append({"kind": "security", "username": reviewer, "status": "pending"})
    if not steps:
        raise Unassignable("No approver could be assigned.")
    return steps


def can_decide(steps: list[dict], actor: str, target: str, requester: str) -> tuple[bool, str]:
    if actor in {target, requester}:
        return False, "The requester and the target identity cannot approve this request."
    pending = [step for step in steps if step["status"] == "pending"]
    if not pending:
        return False, "This request has no pending approval."
    current = pending[0]
    if actor != current["username"]:
        return False, f"This step is assigned to {current['username']}."
    return True, current["kind"]

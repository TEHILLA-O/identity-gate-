"""Access-review decision rules."""

from __future__ import annotations


def can_certify(reviewer: str, target: str) -> tuple[bool, str]:
    if reviewer == target:
        return False, "A person cannot certify their own access."
    return True, ""


def remediation_for(decision: str) -> str:
    if decision == "approve":
        return "not_required"
    if decision == "revoke":
        return "pending_removal"
    if decision == "clarification":
        return "not_required"
    raise ValueError(f"unsupported decision {decision}")

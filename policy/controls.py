"""Evidence rules for illustrative NIST SP 800-53 checks.

Missing evidence stays not_evaluated. These checks do not certify compliance.
"""

from __future__ import annotations


def _result(status: str, summary: str, evidence: list, limitations: str) -> dict:
    return {"status": status, "summary": summary, "evidence": evidence, "limitations": limitations}


def account_lifecycle(identities: list[dict]) -> dict:
    departed = [item for item in identities if item["employment_status"] == "departed"]
    if not departed:
        return _result(
            "not_evaluated",
            "No departed identities were in the evaluation set.",
            [],
            "A passing result requires at least one departed identity whose Keycloak account was observed disabled.",
        )
    enabled = [item["employee_number"] for item in departed if item.get("kc_enabled")]
    if enabled:
        return _result(
            "failed",
            "One or more departed identities still have an enabled Keycloak account.",
            [{"employee_numbers": enabled}],
            "Observation is point-in-time. Downstream accounts are assessed by a separate check.",
        )
    return _result(
        "passed",
        "Every departed identity in scope has a disabled Keycloak account.",
        [{"employee_numbers": [item["employee_number"] for item in departed]}],
        "Disabling the account does not by itself prove that previously issued access tokens are gone.",
    )


def deprovisioning(leavers: list[dict], downstream: list[dict]) -> dict:
    if not leavers:
        return _result(
            "not_evaluated",
            "No leaver workflow has been recorded in this assessment window.",
            [],
            "Absence of a failed leaver is not evidence that deprovisioning works.",
        )
    failed = [item["id"] for item in leavers if item["status"] != "succeeded"]
    stale = [item["employee_number"] for item in downstream if item.get("employment_status") == "departed" and item.get("downstream_active")]
    if failed or stale:
        return _result(
            "failed",
            "A leaver workflow failed or a departed identity is still active downstream.",
            [{"failed_workflows": failed, "downstream_active": stale}],
            "Token expiry is separate from downstream account state.",
        )
    return _result(
        "passed",
        "Recorded leaver workflows succeeded and departed identities are inactive downstream.",
        [{"workflows": len(leavers)}],
        "Only connected downstream directories are visible to this check.",
    )


def separation_of_duties(conflicts: list[dict]) -> dict:
    open_high = [item for item in conflicts if item["status"] == "open" and item["severity"] == "high"]
    if open_high:
        return _result(
            "failed",
            "High-severity segregation conflicts are open.",
            [{"rule_ids": sorted({item["rule_id"] for item in open_high}), "subjects": [item["subject"] for item in open_high]}],
            "Excepted conflicts remain visible and do not count as resolved.",
        )
    if not conflicts:
        return _result(
            "needs_review",
            "No segregation conflicts were detected. Confirm the policy catalogue covers the applications in scope.",
            [],
            "A detector that sees nothing is not, by itself, proof that duties are separated.",
        )
    return _result(
        "passed",
        "No open high-severity segregation conflicts were detected.",
        [{"open": [item for item in conflicts if item["status"] == "open"], "excepted": [item["subject"] for item in conflicts if item["status"] == "excepted"]}],
        "The catalogue is illustrative and only evaluates configured rules.",
    )


def least_privilege(grants: list[dict]) -> dict:
    missing = [item for item in grants if item.get("privileged") and not item.get("approval_id") and item.get("active", True)]
    if missing:
        return _result(
            "failed",
            "Privileged access is present without a linked approval.",
            [{"grants": missing}],
            "Birthright roles are not treated as privileged.",
        )
    if not grants:
        return _result("not_evaluated", "No grants were available to assess.", [], "The entitlement projection was empty.")
    return _result(
        "passed",
        "Every active privileged grant in the projection has an approval record.",
        [{"privileged_grants": len([item for item in grants if item.get("privileged")])}],
        "The check uses IdentityGate grant evidence, not a scan of every external application.",
    )


def audit_generation(events: int, chain_valid: bool | None) -> dict:
    if events == 0 or chain_valid is None:
        return _result(
            "not_evaluated",
            "No governance audit events were available to verify.",
            [],
            "An empty audit trail is not a passing control.",
        )
    if not chain_valid:
        return _result("failed", "The audit hash chain did not verify.", [{"events": events}], "The chain detects tampering; it does not prevent a privileged database rewrite.")
    return _result(
        "passed",
        "Governance audit events are present and the hash chain verifies.",
        [{"events": events}],
        "The chain's trust anchor lives in the same database. This is tamper evidence, not immutability.",
    )


def configuration(redirects: list[dict]) -> dict:
    if not redirects:
        return _result("not_evaluated", "Client redirect URIs were not read from Keycloak.", [], "The admin API observation was missing.")
    wild = [item for item in redirects if any("*" in uri for uri in item["uris"])]
    if wild:
        return _result("failed", "A client allows a wildcard redirect URI.", wild, "Local demo clients are expected to use exact redirect URIs.")
    return _result("passed", "Observed clients use exact redirect URIs.", redirects, "Only the clients returned by this observation were checked.")

from datetime import datetime, timezone

from policy.approvals import Unassignable, approval_plan, can_decide
from policy.audit_chain import GENESIS, link, verify
from policy.controls import (
    account_lifecycle,
    audit_generation,
    configuration,
    deprovisioning,
    least_privilege,
    separation_of_duties,
)
from policy.decision import decision, is_allowed, load_catalog, load_matrix
from policy.entitlements import (
    access_paths,
    birthright_groups,
    compare_paths,
    diff_assignments,
    groups_after_move,
    summarise,
)
from policy.reviews import can_certify, remediation_for
from policy.sod import evaluate

MATRIX = load_matrix()
CATALOG = load_catalog()


def test_finance_reader_cannot_approve_or_create():
    roles = {"finance-reader"}
    assert is_allowed(MATRIX, "northstar-finance", "report:read", roles)
    assert not is_allowed(MATRIX, "northstar-finance", "report:create", roles)
    denied = decision(MATRIX, "northstar-finance", "payment:approve", roles)
    assert denied["allowed"] is False
    assert "finance-approver" in denied["reason"]


def test_analyst_can_create_but_not_approve():
    roles = {"finance-reader", "finance-analyst"}
    assert is_allowed(MATRIX, "northstar-finance", "report:create", roles)
    assert not is_allowed(MATRIX, "northstar-finance", "payment:approve", roles)


def test_admin_configures_without_payment_approval():
    roles = {"finance-admin", "finance-reader"}
    assert is_allowed(MATRIX, "northstar-finance", "app:configure", roles)
    assert not is_allowed(MATRIX, "northstar-finance", "payment:approve", roles)
    assert not is_allowed(MATRIX, "northstar-finance", "report:create", roles)


def test_effective_path_through_finance_group():
    paths = access_paths(["dept-finance", "company-directory"], {}, [], catalog=CATALOG, matrix=MATRIX)
    summary = summarise(paths)
    read = [item for item in summary["permissions"] if item["permission"] == "report:read"]
    assert read
    assert any(path["group"] == "dept-finance" and path["role"] == "finance-reader" for path in read[0]["paths"])
    assert not any(item["permission"] == "payment:approve" for item in summary["permissions"])


def test_unresolved_effective_role_is_visible():
    paths = access_paths([], {}, [], effective_client={"northstar-finance": ["finance-approver"]}, catalog=CATALOG, matrix=MATRIX)
    assert any(path["source"] == "unresolved" and path["role"] == "finance-approver" for path in paths)


def test_duplicate_paths_keep_one_permission():
    paths = access_paths(
        ["dept-finance"],
        {"northstar-finance": ["finance-reader"]},
        [],
        catalog=CATALOG,
        matrix=MATRIX,
    )
    summary = summarise(paths)
    reads = [item for item in summary["permissions"] if item["permission"] == "report:read"]
    assert len(reads) == 1
    assert len(reads[0]["paths"]) == 2


def test_mover_removes_finance_privilege_and_adds_engineering():
    person = {
        "department": "Finance",
        "employment_type": "employee",
        "extra_groups": [{"group": "finance-analysts"}, {"group": "identity-reviewers"}],
    }
    before = ["company-directory", "dept-finance", "finance-analysts", "identity-reviewers"]
    after = groups_after_move(person, "Engineering", CATALOG)
    diff = diff_assignments(before, after, {}, {}, CATALOG)
    removed = {(item["application"], item["role"]) for item in diff["removed"]}
    added = {(item["application"], item["role"]) for item in diff["added"]}
    unchanged = {(item["application"], item["role"]) for item in diff["unchanged"]}
    assert ("northstar-finance", "finance-analyst") in removed
    assert ("northstar-finance", "finance-reader") in removed
    assert ("northstar-projects", "project-contributor") in added
    assert ("northstar-projects", "project-reader") in added
    assert ("realm", "employee") in unchanged
    assert "identity-reviewers" in after
    assert "finance-analysts" not in after


def test_service_account_skips_department_birthright():
    groups = birthright_groups({"department": "Finance", "employment_type": "service"}, CATALOG)
    assert groups == ["service-accounts"]


def test_sod_detects_create_and_approve():
    conflicts = evaluate(
        MATRIX,
        {"northstar-finance": {"finance-analyst", "finance-approver"}},
        set(),
        subject="marcus.hale",
    )
    assert len(conflicts) == 1
    assert conflicts[0]["rule_id"] == "SOD-FIN-01"
    assert conflicts[0]["status"] == "open"


def test_sod_exception_does_not_clear_the_conflict():
    expiry = "2026-12-01T00:00:00Z"
    conflicts = evaluate(
        MATRIX,
        {"northstar-finance": ["finance-analyst", "finance-approver"]},
        [],
        subject="marcus.hale",
        exceptions=[{
            "rule_id": "SOD-FIN-01",
            "subject": "marcus.hale",
            "state": "active",
            "expires_at": expiry,
        }],
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
    )
    assert conflicts[0]["status"] == "excepted"
    assert conflicts[0]["exception"]["expires_at"] == expiry


def test_expired_exception_reopens_conflict():
    conflicts = evaluate(
        MATRIX,
        {"northstar-finance": ["finance-analyst", "finance-approver"]},
        [],
        subject="marcus.hale",
        exceptions=[{
            "rule_id": "SOD-FIN-01",
            "subject": "marcus.hale",
            "state": "active",
            "expires_at": "2026-01-01T00:00:00Z",
        }],
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
    )
    assert conflicts[0]["status"] == "open"


def test_analyst_alone_is_not_a_conflict():
    assert evaluate(MATRIX, {"northstar-finance": ["finance-analyst"]}, [], subject="elena.vasquez") == []


def test_requester_cannot_approve_and_cannot_choose_approver():
    steps = approval_plan(
        target="elena.vasquez",
        requester="elena.vasquez",
        manager="priya.nair",
        role="finance-approver",
        privileged_roles=set(MATRIX["privileged_roles"]),
        security_reviewer="amira.shah",
        independent_reviewer="helen.cho",
    )
    assert [step["username"] for step in steps] == ["priya.nair", "amira.shah"]
    allowed, _ = can_decide(steps, "elena.vasquez", "elena.vasquez", "elena.vasquez")
    assert not allowed
    allowed, kind = can_decide(steps, "priya.nair", "elena.vasquez", "elena.vasquez")
    assert allowed and kind == "manager"
    allowed, _ = can_decide(steps, "amira.shah", "elena.vasquez", "elena.vasquez")
    assert not allowed


def test_manager_requester_is_skipped():
    steps = approval_plan(
        target="elena.vasquez",
        requester="priya.nair",
        manager="priya.nair",
        role="finance-analyst",
        privileged_roles=set(MATRIX["privileged_roles"]),
        security_reviewer="amira.shah",
        independent_reviewer="helen.cho",
    )
    assert steps[0]["username"] == "amira.shah"


def test_unassignable_when_every_reviewer_is_the_target():
    try:
        approval_plan(
            target="amira.shah",
            requester="amira.shah",
            manager=None,
            role="identitygate-admin",
            privileged_roles=set(MATRIX["privileged_roles"]),
            security_reviewer="amira.shah",
            independent_reviewer="amira.shah",
        )
        raised = False
    except Unassignable:
        raised = True
    assert raised


def test_self_review_is_blocked():
    allowed, reason = can_certify("elena.vasquez", "elena.vasquez")
    assert not allowed
    assert "own access" in reason
    assert can_certify("priya.nair", "elena.vasquez")[0]


def test_revoke_is_not_removal():
    assert remediation_for("approve") == "not_required"
    assert remediation_for("revoke") == "pending_removal"


def test_hash_chain_detects_tampering():
    first = {"event": "join", "actor": "owen.briggs"}
    second = {"event": "approve", "actor": "priya.nair"}
    row1 = {"payload": first, "prev_hash": GENESIS, "row_hash": link(GENESIS, first)}
    row2 = {"payload": second, "prev_hash": row1["row_hash"], "row_hash": link(row1["row_hash"], second)}
    assert verify([row1, row2])["valid"]
    row2["payload"] = {"event": "approve", "actor": "elena.vasquez"}
    assert verify([row1, row2])["valid"] is False


def test_controls_do_not_pass_without_evidence():
    assert account_lifecycle([])["status"] == "not_evaluated"
    assert deprovisioning([], [])["status"] == "not_evaluated"
    assert audit_generation(0, None)["status"] == "not_evaluated"
    assert configuration([])["status"] == "not_evaluated"


def test_controls_fail_on_real_conditions():
    failed = account_lifecycle([{"employee_number": "NS-1", "employment_status": "departed", "kc_enabled": True}])
    assert failed["status"] == "failed"
    passed = account_lifecycle([{"employee_number": "NS-1", "employment_status": "departed", "kc_enabled": False}])
    assert passed["status"] == "passed"
    sod = separation_of_duties([{"rule_id": "SOD-FIN-01", "severity": "high", "status": "open", "subject": "marcus.hale"}])
    assert sod["status"] == "failed"
    privilege = least_privilege([{"privileged": True, "approval_id": None, "active": True, "role": "project-admin"}])
    assert privilege["status"] == "failed"
    wild = configuration([{"client": "demo", "uris": ["http://localhost/*"]}])
    assert wild["status"] == "failed"


def test_compare_identities():
    left = access_paths(["dept-finance", "finance-analysts"], {}, [], catalog=CATALOG, matrix=MATRIX)
    right = access_paths(["dept-engineering"], {}, [], catalog=CATALOG, matrix=MATRIX)
    diff = compare_paths(left, right)
    assert any(item["permission"] == "report:create" for item in diff["left_only"])
    assert any(item["permission"] == "project:write" for item in diff["right_only"])
    assert not any(item["permission"] == "report:read" for item in diff["shared"])

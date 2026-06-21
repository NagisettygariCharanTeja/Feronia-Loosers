from schemas.models import Finding, ActionPlanStep, DESTRUCTIVE_ACTIONS

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def build_human_label(f: Finding) -> str:
    action_labels = {
        "tag_resource": "Tag",
        "resize_down": "Resize down",
        "resize_up": "Resize up",
        "flag_for_review": "Flag for review",
        "create_snapshot": "Create snapshot",
        "enable_encryption": "Enable encryption",
        "restrict_security_group": "Restrict security group",
        "rotate_credentials": "Rotate credentials",
        "disable_public_access": "Disable public access",
        "terminate_instance": "Terminate instance",
        "delete_volume": "Delete volume",
        "delete_database": "Delete database",
        "revoke_all_access": "Revoke all access",
        "delete_iam_role": "Delete IAM role",
        "force_stop": "Force stop",
        "enforce_imdsv2": "Enforce IMDSv2",
        "flag_privesc_path": "Flag privilege escalation path",
    }
    label = action_labels.get(f.recommended_action, f.recommended_action)
    return f"{label} — {f.affected_node}"


def synthesize(findings: list[Finding]) -> tuple[list[Finding], list[ActionPlanStep]]:
    seen = set()
    deduped = []
    for f in findings:
        key = (f.affected_node, f.recommended_action)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    sorted_findings = sorted(
        deduped,
        key=lambda f: (
            SEVERITY_ORDER[f.severity],
            -f.confidence,
            f.affected_node,
            f.finding_id,
        ),
    )

    action_plan = []
    for i, f in enumerate(sorted_findings, 1):
        is_destructive = f.recommended_action in DESTRUCTIVE_ACTIONS
        step = ActionPlanStep(
            step=i,
            action=f.recommended_action,
            target_node=f.affected_node,
            human_label=build_human_label(f),
            justification=f.plain_english,
            action_type="destructive" if is_destructive else "safe",
            requires_approval=is_destructive,
            savings_usd_month=(
                f.quantified_impact.get("resize_savings_usd_month", 0)
                if f.quantified_impact
                else 0
            ),
            co2_reduction_kg=(
                f.quantified_impact.get("kg_co2_per_month", 0)
                if f.quantified_impact
                else 0
            ),
            finding_id=f.finding_id,
        )
        action_plan.append(step)

    return sorted_findings, action_plan

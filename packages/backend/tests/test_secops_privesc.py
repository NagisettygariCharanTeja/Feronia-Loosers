import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import json
from schemas.models import Finding
from agents.secops_agent import compute_iam_privesc_paths
from agents.gatekeeper import validate_finding
from graph.builder import build_graph

DATA_DIR = Path(__file__).parent.parent / "data"


def _load_infra():
    return json.loads((DATA_DIR / "infrastructure_state.json").read_text())


def _load_privesc_combos():
    return json.loads((DATA_DIR / "iam_privesc_permissions.json").read_text())


def _build_nx():
    return build_graph(_load_infra())


def test_imdsv2_finding_triggers_on_optional_tokens():
    infra = _load_infra()
    g = _build_nx()
    finding = Finding(
        agent_source="secops",
        severity="high",
        confidence=0.95,
        affected_node="i-0abc123def456",
        description="EC2 instance does not enforce IMDSv2",
        plain_english="This server allows the old, less secure metadata service, making it vulnerable to credential theft.",
        recommended_action="enforce_imdsv2",
        evidence_path=["i-0abc123def456"],
        cis_rule="CIS 5.6",
        mitre_technique="T1552.005",
    )
    passed, errors = validate_finding(finding, g, infra, {})
    assert passed is True
    assert errors == []


def test_privesc_combo_detected_when_permissions_present():
    infra = _load_infra()
    combos = _load_privesc_combos()
    role = next(r for r in infra["resources"] if r["id"] == "arn:aws:iam::123456789012:role/bim-processor-role")
    matches = compute_iam_privesc_paths(role, combos)
    matched_ids = {m["id"] for m in matches}
    assert "iam_privesc_by_passrole_lambda" in matched_ids
    assert "iam_privesc_by_policy_version" in matched_ids


def test_privesc_combo_not_flagged_when_permissions_absent():
    combos = _load_privesc_combos()
    safe_role = {
        "id": "role-safe",
        "type": "iam_role",
        "attached_actions": ["s3:GetObject", "s3:PutObject"],
    }
    matches = compute_iam_privesc_paths(safe_role, combos)
    assert matches == []


def test_gatekeeper_rejects_fabricated_privesc_evidence():
    infra = _load_infra()
    g = _build_nx()
    finding = Finding(
        agent_source="secops",
        severity="critical",
        confidence=0.9,
        affected_node="arn:aws:iam::123456789012:role/bim-processor-role",
        description="Fabricated privesc path",
        plain_english="This role supposedly can escalate via a permission it does not have.",
        recommended_action="flag_privesc_path",
        evidence_path=["iam:PassRole", "ec2:RunInstances"],
        cis_rule="IAM-PRIVESC",
        mitre_technique="T1078",
    )
    passed, errors = validate_finding(finding, g, infra, {})
    assert passed is False
    assert any("ec2:RunInstances" in e and "possible hallucination" in e for e in errors)


def test_gatekeeper_rejects_role_arn_in_privesc_evidence():
    """Regression: LLM sometimes puts the role ARN in evidence_path instead of
    permission strings. Check 5 must reject this — the ARN is not an IAM action."""
    infra = _load_infra()
    g = _build_nx()
    role_arn = "arn:aws:iam::123456789012:role/bim-processor-role"
    finding = Finding(
        agent_source="secops",
        severity="critical",
        confidence=0.9,
        affected_node=role_arn,
        description="Privesc via passrole-lambda",
        plain_english="This role can escalate privileges.",
        recommended_action="flag_privesc_path",
        evidence_path=[role_arn],
        cis_rule="IAM-PRIVESC",
        mitre_technique="T1078",
    )
    passed, errors = validate_finding(finding, g, infra, {})
    assert passed is False
    assert any(role_arn in e and "possible hallucination" in e for e in errors)


def test_gatekeeper_passes_valid_permission_privesc_evidence():
    """Paired with the rejection test above: proper permission strings pass."""
    infra = _load_infra()
    g = _build_nx()
    finding = Finding(
        agent_source="secops",
        severity="critical",
        confidence=1.0,
        affected_node="arn:aws:iam::123456789012:role/bim-processor-role",
        description="Privesc via passrole-lambda",
        plain_english="This role can escalate privileges via Lambda.",
        recommended_action="flag_privesc_path",
        evidence_path=["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        cis_rule="IAM-PRIVESC",
        mitre_technique="T1078",
    )
    passed, errors = validate_finding(finding, g, infra, {})
    assert passed is True
    assert errors == []

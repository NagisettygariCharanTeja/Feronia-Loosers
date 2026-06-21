import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import json
import networkx as nx
from schemas.models import Finding
from agents.gatekeeper import validate_finding
from graph.builder import build_graph

DATA_DIR = Path(__file__).parent.parent / "data"


def _load_infra():
    return json.loads((DATA_DIR / "infrastructure_state.json").read_text())


def _build_nx():
    return build_graph(_load_infra())


def test_valid_safe_action_passes():
    infra = _load_infra()
    g = _build_nx()
    finding = Finding(
        agent_source="secops",
        severity="high",
        confidence=0.9,
        affected_node="sg-0xyz789abc",
        description="Open SSH port",
        plain_english="The security group allows SSH from anywhere.",
        recommended_action="restrict_security_group",
        evidence_path=["sg-0xyz789abc"],
    )
    passed, errors = validate_finding(finding, g, infra, {})
    assert passed is True
    assert errors == []


def test_unrecognised_action_fails():
    infra = _load_infra()
    g = _build_nx()
    finding = Finding(
        agent_source="secops",
        severity="medium",
        confidence=0.8,
        affected_node="sg-0xyz789abc",
        description="Some issue",
        plain_english="Something is wrong.",
        recommended_action="nuke_from_orbit",
        evidence_path=[],
    )
    passed, errors = validate_finding(finding, g, infra, {})
    assert passed is False
    assert any("Unrecognised action" in e for e in errors)


def test_nonexistent_node_fails():
    infra = _load_infra()
    g = _build_nx()
    finding = Finding(
        agent_source="secops",
        severity="high",
        confidence=0.9,
        affected_node="i-doesnotexist",
        description="Phantom node",
        plain_english="This node does not exist.",
        recommended_action="flag_for_review",
        evidence_path=[],
    )
    passed, errors = validate_finding(finding, g, infra, {})
    assert passed is False
    assert any("possible hallucination" in e.lower() for e in errors)


def test_valid_node_passes():
    infra = _load_infra()
    g = _build_nx()
    finding = Finding(
        agent_source="secops",
        severity="medium",
        confidence=0.7,
        affected_node="i-0abc123def456",
        description="EC2 with public exposure",
        plain_english="An EC2 instance is publicly accessible.",
        recommended_action="disable_public_access",
        evidence_path=["i-0abc123def456"],
    )
    passed, errors = validate_finding(finding, g, infra, {})
    assert passed is True
    assert errors == []


def test_gatekeeper_rejects_action_node_type_mismatch():
    infra = _load_infra()
    g = _build_nx()
    finding = Finding(
        agent_source="greenops",
        severity="medium",
        confidence=0.8,
        affected_node="vol-0unattached456",
        description="Zombie EBS volume",
        plain_english="This volume is unattached and wasting money.",
        recommended_action="terminate_instance",
        evidence_path=["vol-0unattached456"],
        quantified_impact={"monthly_cost_usd": 50, "wasted_cost_usd": 50,
                           "resize_savings_usd_month": 0, "kg_co2_per_month": 0,
                           "region_carbon_intensity": 620},
    )
    passed, errors = validate_finding(finding, g, infra, {})
    assert passed is False
    assert any("not valid for node type" in e for e in errors)


def test_terminate_instance_valid_on_ec2():
    infra = _load_infra()
    g = _build_nx()
    finding = Finding(
        agent_source="greenops",
        severity="high",
        confidence=0.9,
        affected_node="i-0zombie999",
        description="Zombie EC2 instance",
        plain_english="This server is idle and wasting money.",
        recommended_action="terminate_instance",
        evidence_path=["i-0zombie999"],
        quantified_impact={"monthly_cost_usd": 248, "wasted_cost_usd": 248,
                           "resize_savings_usd_month": 0, "kg_co2_per_month": 36,
                           "region_carbon_intensity": 620},
    )
    passed, errors = validate_finding(finding, g, infra, {})
    assert passed is True
    assert errors == []

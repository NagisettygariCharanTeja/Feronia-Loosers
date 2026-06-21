import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import json
from unittest.mock import patch, MagicMock

from schemas.models import Finding, ActionPlanStep
from pipeline.ingestor import ingest_logs
from graph.builder import build_graph
from agents.gatekeeper import run_gatekeeper
from pipeline.synthesizer import synthesize

DATA_DIR = Path(__file__).parent.parent / "data"
OUTPUT_DIR = Path(__file__).parent.parent / "output"


def _load_infra():
    return json.loads((DATA_DIR / "infrastructure_state.json").read_text())


def _load_logs():
    return json.loads((DATA_DIR / "mock_logs.json").read_text())


def test_ingestor_counts():
    raw = _load_logs()
    valid, corrupted = ingest_logs(raw)
    assert len(valid) == 9
    assert len(corrupted) == 1
    assert (OUTPUT_DIR / "corrupted_logs.jsonl").exists()


def test_graph_builds_without_crash():
    """Validates graph construction against data/infrastructure_state.json (mock data).
    Real AWS scan counts will differ — run aws_scanner.py standalone to verify those."""
    infra = _load_infra()
    g = build_graph(infra)
    assert g.number_of_nodes() == len(infra["resources"])
    assert g.number_of_edges() == len(infra["relationships"])


def _mock_findings(infra: dict) -> list[Finding]:
    return [
        Finding(
            agent_source="secops",
            severity="critical",
            confidence=0.95,
            affected_node="sg-0xyz789abc",
            description="Open SSH to world",
            plain_english="The security group allows SSH from anywhere on the internet.",
            recommended_action="restrict_security_group",
            evidence_path=["sg-0xyz789abc", "i-0abc123def456"],
            cis_rule="CIS 4.1",
            mitre_technique="T1190",
        ),
        Finding(
            agent_source="secops",
            severity="high",
            confidence=0.9,
            affected_node="s3-hilti-bim-models",
            description="Public S3 bucket",
            plain_english="The BIM models storage bucket is publicly accessible.",
            recommended_action="disable_public_access",
            evidence_path=["s3-hilti-bim-models"],
            cis_rule="CIS 2.1.1",
        ),
        Finding(
            agent_source="greenops",
            severity="medium",
            confidence=0.85,
            affected_node="i-0abc123def456",
            description="Overprovisioned m5.4xlarge at 4.2% CPU",
            plain_english="This server is much larger than it needs to be, wasting money.",
            recommended_action="resize_down",
            evidence_path=["i-0abc123def456"],
            quantified_impact={
                "monthly_cost_usd": 560.64,
                "wasted_cost_usd": 280.32,
                "resize_savings_usd_month": 499.98,
                "kg_co2_per_month": 72.27,
                "region_carbon_intensity": 620,
            },
        ),
        Finding(
            agent_source="greenops",
            severity="high",
            confidence=0.9,
            affected_node="i-0zombie999",
            description="Zombie instance at 0.8% CPU",
            plain_english="This server is doing almost nothing but still costing money.",
            recommended_action="terminate_instance",
            evidence_path=["i-0zombie999"],
            quantified_impact={
                "monthly_cost_usd": 248.2,
                "wasted_cost_usd": 124.1,
                "resize_savings_usd_month": 187.46,
                "kg_co2_per_month": 36.21,
                "region_carbon_intensity": 620,
            },
        ),
    ]


def test_full_pipeline_mock():
    infra = _load_infra()
    g = build_graph(infra)
    findings = _mock_findings(infra)

    validated, errors, retry_count = run_gatekeeper(findings, g, infra)
    assert len(validated) > 0

    sorted_findings, action_plan = synthesize(validated)

    OUTPUT_DIR.mkdir(exist_ok=True)
    dashboard = {
        "findings": [f.model_dump(mode="json") for f in sorted_findings],
        "action_plan": [s.model_dump(mode="json") for s in action_plan],
        "summary": {
            "total_findings": len(sorted_findings),
            "total_actions": len(action_plan),
        },
    }
    with open(OUTPUT_DIR / "dashboard.json", "w") as f:
        json.dump(dashboard, f, indent=2, default=str)

    assert (OUTPUT_DIR / "dashboard.json").exists()
    loaded = json.loads((OUTPUT_DIR / "dashboard.json").read_text())
    assert "findings" in loaded
    assert "action_plan" in loaded
    assert "summary" in loaded


def test_no_hallucinated_nodes_in_action_plan():
    infra = _load_infra()
    g = build_graph(infra)
    resource_ids = {r["id"] for r in infra["resources"]}

    findings = _mock_findings(infra)
    validated, _, _ = run_gatekeeper(findings, g, infra)
    _, action_plan = synthesize(validated)

    for step in action_plan:
        assert step.target_node in resource_ids, (
            f"Action plan step references non-existent node: {step.target_node}"
        )


def test_execute_node_calls_real_actions_with_correct_steps():
    """Verify execute_node wiring: calls execute_real_actions with the right
    approved steps list without making real AWS API calls."""
    import importlib
    import execute_aws_actions
    import graph.workflow as wf_mod

    infra = _load_infra()

    safe_step = ActionPlanStep(
        step=1, action="restrict_security_group", target_node="sg-0xyz789abc",
        human_label="Restrict SG", justification="Open SSH",
        action_type="safe", requires_approval=False, finding_id="f1",
    )
    destructive_step = ActionPlanStep(
        step=2, action="terminate_instance", target_node="i-0zombie999",
        human_label="Terminate zombie", justification="Idle",
        action_type="destructive", requires_approval=True, finding_id="f2",
    )

    mock_logs = [
        {"timestamp": "t", "step": 1, "status": "complete", "message": "ok"},
        {"timestamp": "t", "step": 2, "status": "complete", "message": "ok"},
    ]

    original_fn = wf_mod.execute_real_actions
    mock_exec = MagicMock(return_value=mock_logs)
    wf_mod.execute_real_actions = mock_exec
    try:
        # Case 1: approved — both steps should be passed
        state_approved = {
            "hitl_decision": "approve",
            "action_plan": [safe_step, destructive_step],
            "infrastructure": infra,
        }
        wf_mod.execute_node(state_approved)
        called_steps = mock_exec.call_args[0][0]
        assert len(called_steps) == 2

        # Case 2: rejected — only safe step passed
        mock_exec.reset_mock()
        mock_exec.return_value = mock_logs[:1]
        state_rejected = {
            "hitl_decision": "reject",
            "action_plan": [safe_step, destructive_step],
            "infrastructure": infra,
        }
        wf_mod.execute_node(state_rejected)
        called_steps = mock_exec.call_args[0][0]
        assert len(called_steps) == 1
        assert called_steps[0].action == "restrict_security_group"
    finally:
        wf_mod.execute_real_actions = original_fn


def test_execute_real_actions_dispatches_without_aws():
    """Confirm execute_real_actions dispatches to the correct handler per action
    type, using mocked boto3 clients — no real AWS calls."""
    import execute_aws_actions as ea

    infra = _load_infra()

    step = ActionPlanStep(
        step=1, action="tag_resource", target_node="sg-0xyz789abc",
        human_label="Tag SG", justification="Review",
        action_type="safe", requires_approval=False, finding_id="f1",
    )

    original_ec2 = ea.ec2
    ea.ec2 = MagicMock()
    try:
        logs = ea.execute_real_actions([step], infra)
        assert len(logs) == 1
        assert logs[0]["status"] == "complete"
        ea.ec2.create_tags.assert_called_once()
    finally:
        ea.ec2 = original_ec2

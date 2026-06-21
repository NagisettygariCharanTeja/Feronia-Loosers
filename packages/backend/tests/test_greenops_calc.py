import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import json
from schemas.models import Finding
from agents.greenops_agent import (
    compute_greenops_impact,
    _compute_instance_co2,
    _compute_ebs_co2,
    CCF_MIN_WATTS_PER_VCPU,
    CCF_MAX_WATTS_PER_VCPU,
    CCF_AWS_PUE,
    CCF_SSD_WH_PER_TB_HOUR,
    HOURS_PER_MONTH,
)

DATA_DIR = Path(__file__).parent.parent / "data"


def _load_static_data():
    pricing = json.loads((DATA_DIR / "instance_pricing.json").read_text())
    carbon = json.loads((DATA_DIR / "carbon_intensity.json").read_text())
    thresholds = json.loads((DATA_DIR / "zombie_thresholds.json").read_text())
    return pricing, carbon, thresholds


def _fixture_infra():
    return {
        "resources": [
            {
                "id": "i-fixture-m5-4xl",
                "type": "ec2_instance",
                "instance_type": "m5.4xlarge",
                "region": "ap-southeast-1",
                "cpu_avg_7d": 4.2,
                "state": "running",
            },
            {
                "id": "i-fixture-c5-2xl",
                "type": "ec2_instance",
                "instance_type": "c5.2xlarge",
                "region": "ap-southeast-1",
                "cpu_avg_7d": 0.8,
                "state": "running",
            },
        ]
    }


def _make_finding(node_id: str) -> Finding:
    return Finding(
        agent_source="greenops",
        severity="medium",
        confidence=0.8,
        affected_node=node_id,
        description="Overprovisioned instance",
        plain_english="This instance is too big for its workload.",
        recommended_action="resize_down",
        evidence_path=[node_id],
    )


def test_monthly_cost_m5_4xlarge():
    pricing, carbon, thresholds = _load_static_data()
    infra = _fixture_infra()
    finding = _make_finding("i-fixture-m5-4xl")
    result = compute_greenops_impact(finding, infra, pricing, carbon, thresholds)
    expected = round(0.768 * 730, 2)
    assert result.quantified_impact is not None
    assert abs(result.quantified_impact["monthly_cost_usd"] - expected) < 0.01


def test_quantified_impact_always_populated():
    pricing, carbon, thresholds = _load_static_data()
    infra = _fixture_infra()
    finding = _make_finding("i-fixture-c5-2xl")
    result = compute_greenops_impact(finding, infra, pricing, carbon, thresholds)
    assert result.quantified_impact is not None
    assert "monthly_cost_usd" in result.quantified_impact
    assert "kg_co2_per_month" in result.quantified_impact


def test_resize_savings_positive_for_large_instance():
    pricing, carbon, thresholds = _load_static_data()
    infra = _fixture_infra()
    finding = _make_finding("i-fixture-m5-4xl")
    result = compute_greenops_impact(finding, infra, pricing, carbon, thresholds)
    assert result.quantified_impact is not None
    assert result.quantified_impact["resize_savings_usd_month"] > 0


def test_terminate_instance_savings_equals_full_monthly_cost():
    pricing, carbon, thresholds = _load_static_data()
    infra = _fixture_infra()
    finding = Finding(
        agent_source="greenops",
        severity="high",
        confidence=0.9,
        affected_node="i-fixture-c5-2xl",
        description="Zombie instance",
        plain_english="This server is idle.",
        recommended_action="terminate_instance",
        evidence_path=["i-fixture-c5-2xl"],
    )
    result = compute_greenops_impact(finding, infra, pricing, carbon, thresholds)
    qi = result.quantified_impact
    assert qi is not None
    expected_cost = round(0.34 * 730, 2)
    assert qi["resize_savings_usd_month"] == expected_cost
    assert qi["monthly_cost_usd"] == expected_cost
    assert qi["kg_co2_per_month"] > 0


def test_delete_volume_savings_equals_full_monthly_cost():
    pricing, carbon, thresholds = _load_static_data()
    infra = {
        "resources": [{
            "id": "vol-fixture",
            "type": "ebs_volume",
            "size_gb": 500,
            "region": "ap-southeast-1",
            "state": "available",
            "attached_to": None,
        }]
    }
    finding = Finding(
        agent_source="greenops",
        severity="medium",
        confidence=0.8,
        affected_node="vol-fixture",
        description="Unattached volume",
        plain_english="This volume is wasting money.",
        recommended_action="delete_volume",
        evidence_path=["vol-fixture"],
    )
    result = compute_greenops_impact(finding, infra, pricing, carbon, thresholds)
    qi = result.quantified_impact
    assert qi is not None
    assert qi["monthly_cost_usd"] == 50.0
    assert qi["resize_savings_usd_month"] == 50.0


def test_owned_or_dependent_instance_never_recommended_for_termination():
    """An instance with a known owner or iam_profile should get resize_down,
    not terminate_instance. This test documents the disambiguation rule — the
    LLM prompt enforces it, and this verifies the impact calc correctly
    produces a resize delta (not full-cost savings) for such findings."""
    pricing, carbon, thresholds = _load_static_data()
    infra = {
        "resources": [{
            "id": "i-owned",
            "type": "ec2_instance",
            "instance_type": "m5.4xlarge",
            "region": "ap-southeast-1",
            "cpu_avg_7d": 3.0,
            "state": "running",
            "tags": {"owner": "team-alpha"},
            "iam_profile": "arn:aws:iam::123456789012:role/some-role",
        }]
    }
    finding = Finding(
        agent_source="greenops",
        severity="medium",
        confidence=0.8,
        affected_node="i-owned",
        description="Overprovisioned but owned",
        plain_english="This server is too big.",
        recommended_action="resize_down",
        evidence_path=["i-owned"],
    )
    result = compute_greenops_impact(finding, infra, pricing, carbon, thresholds)
    qi = result.quantified_impact
    full_cost = round(0.768 * 730, 2)
    assert qi["resize_savings_usd_month"] > 0
    assert qi["resize_savings_usd_month"] < full_cost


def test_unowned_idle_instance_with_no_dependency_recommended_for_termination():
    """An instance with owner=unknown and no iam_profile, below 10% CPU,
    should be recommended for terminate_instance. Savings must equal the
    full monthly cost."""
    pricing, carbon, thresholds = _load_static_data()
    infra = {
        "resources": [{
            "id": "i-zombie",
            "type": "ec2_instance",
            "instance_type": "c5.2xlarge",
            "region": "ap-southeast-1",
            "cpu_avg_7d": 0.8,
            "state": "running",
            "tags": {"owner": "unknown"},
            "iam_profile": None,
        }]
    }
    finding = Finding(
        agent_source="greenops",
        severity="high",
        confidence=0.9,
        affected_node="i-zombie",
        description="Zombie instance",
        plain_english="Idle with no owner.",
        recommended_action="terminate_instance",
        evidence_path=["i-zombie"],
    )
    result = compute_greenops_impact(finding, infra, pricing, carbon, thresholds)
    qi = result.quantified_impact
    expected_cost = round(0.34 * 730, 2)
    assert qi["resize_savings_usd_month"] == expected_cost
    assert qi["kg_co2_per_month"] > 0


def test_compute_watts_formula_matches_ccf_methodology():
    """Verify _compute_instance_co2 against a hand-calculated CCF example.
    c5.2xlarge (8 vCPUs) at 0.8% CPU in ap-southeast-1 (0.49453 kg/kWh):
      Avg W/vCPU = 0.74 + 0.008 * (3.5 - 0.74) = 0.76208
      Total W    = 0.76208 * 8 = 6.09664
      kWh/month  = 6.09664 * 730 / 1000 = 4.450547
      CO2 kg     = 4.450547 * 1.135 * 0.49453 = ~2.499
    """
    intensity = 0.49453
    vcpus = 8
    utilization = 0.008
    result = _compute_instance_co2(vcpus, utilization, intensity)

    avg_w = CCF_MIN_WATTS_PER_VCPU + utilization * (CCF_MAX_WATTS_PER_VCPU - CCF_MIN_WATTS_PER_VCPU)
    total_w = avg_w * vcpus
    kwh = total_w * HOURS_PER_MONTH / 1000
    expected = kwh * CCF_AWS_PUE * intensity

    assert abs(result - round(expected, 4)) < 0.001
    assert 2.0 < result < 3.0


def test_ebs_volume_co2_nonzero_for_unattached_volume():
    """EBS volumes now have real CO2 via CCF's SSD storage coefficient.
    500 GB in ap-southeast-1:
      size_tb = 0.5, kWh = 0.5 * 1.2 * 730 / 1000 = 0.438
      CO2 kg  = 0.438 * 1.135 * 0.49453 ≈ 0.2459
    """
    pricing, carbon, thresholds = _load_static_data()
    infra = {
        "resources": [{
            "id": "vol-co2-test",
            "type": "ebs_volume",
            "size_gb": 500,
            "region": "ap-southeast-1",
            "state": "available",
            "attached_to": None,
        }]
    }
    finding = Finding(
        agent_source="greenops",
        severity="medium",
        confidence=0.8,
        affected_node="vol-co2-test",
        description="Unattached volume",
        plain_english="Wasting money and energy.",
        recommended_action="delete_volume",
        evidence_path=["vol-co2-test"],
    )
    result = compute_greenops_impact(finding, infra, pricing, carbon, thresholds)
    qi = result.quantified_impact
    assert qi is not None
    assert qi["kg_co2_per_month"] > 0

    expected = _compute_ebs_co2(500, 0.49453)
    assert abs(qi["kg_co2_per_month"] - expected) < 0.001

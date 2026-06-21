import json
import os

from langchain_openai import ChatOpenAI
from pydantic import BaseModel
from rich.console import Console

from schemas.models import Finding

console = Console()

GREENOPS_SYSTEM_PROMPT = """You are a cloud cost and sustainability analyst for Hilti, a construction technology company.
Analyse the provided AWS infrastructure for three categories of waste:

1. ZOMBIE RESOURCES:
   - EC2 instances: use "terminate_instance" ONLY when ALL three conditions are met:
     (a) cpu_avg_7d < 10%
     (b) Owner tag is missing, empty, or "unknown"
     (c) iam_profile is null (no IAM role attached)
     If the instance has a known owner OR an iam_profile, use "resize_down" instead,
     regardless of how low CPU is — the dependency means termination is unsafe.
   - Unattached EBS volumes (state="available", attached_to=null) → use "delete_volume"
   IMPORTANT: terminate_instance is ONLY for EC2 instances. For EBS volumes use delete_volume.

2. RIGHT-SIZING: Instances overprovisioned for their workload.
   Recommend resize_down if cpu_avg_7d < 25% and instance is larger than t3.large.

3. CARBON OPTIMISATION: Workloads in high-carbon regions (ap-southeast-1 = 494.53 gCO2/kWh)
   that could move to lower-carbon regions.

For recommended_action, use ONLY these exact values:
  resize_down, flag_for_review, tag_resource, terminate_instance, delete_volume
Action-to-resource-type rules:
  terminate_instance → EC2 instances ONLY
  delete_volume → EBS volumes ONLY
  resize_down → EC2 instances ONLY

Set quantified_impact to null — the system will calculate exact numbers from pricing tables.
Your job is identification and justification, NOT arithmetic.

CRITICAL: Only reference resource IDs that appear in the infrastructure data provided.
plain_english: one sentence explaining the waste in business terms (avoid AWS jargon).
Set agent_source to "greenops" for all findings."""


class GreenOpsOutput(BaseModel):
    findings: list[Finding]


EBS_COST_PER_GB_MONTH = 0.10
HOURS_PER_MONTH = 730

# Cloud Carbon Footprint (cloudcarbonfootprint.org) methodology constants.
# AWS-specific coefficients are CCF's published averages across AWS instance
# microarchitectures, sourced from SPECpower and AWS documentation.
CCF_MIN_WATTS_PER_VCPU = 0.74
CCF_MAX_WATTS_PER_VCPU = 3.5
CCF_AWS_PUE = 1.135
# SSD storage energy: 1.2 Wh per TB-hour (CCF storage coefficient)
CCF_SSD_WH_PER_TB_HOUR = 1.2

VCPU_MAP = {
    "t3.micro": 2, "t3.large": 2, "t3.xlarge": 4,
    "c5.2xlarge": 8, "m5.4xlarge": 16, "m5.2xlarge": 8,
    "db.t3.large": 2, "r5.2xlarge": 8,
}

FULL_REMOVAL_ACTIONS = {"terminate_instance", "delete_volume", "delete_database"}


def _compute_instance_co2(vcpus: int, utilization_fraction: float,
                          intensity_kg_per_kwh: float) -> float:
    """CCF formula: Avg Watts = Min + utilization * (Max - Min), per vCPU."""
    avg_watts_per_vcpu = (CCF_MIN_WATTS_PER_VCPU
                          + utilization_fraction * (CCF_MAX_WATTS_PER_VCPU - CCF_MIN_WATTS_PER_VCPU))
    total_watts = avg_watts_per_vcpu * vcpus
    kwh = total_watts * HOURS_PER_MONTH / 1000
    return round(kwh * CCF_AWS_PUE * intensity_kg_per_kwh, 4)


def _compute_ebs_co2(size_gb: int, intensity_kg_per_kwh: float) -> float:
    """CCF storage formula: energy = size_TB * coefficient * hours."""
    size_tb = size_gb / 1000
    kwh = size_tb * CCF_SSD_WH_PER_TB_HOUR * HOURS_PER_MONTH / 1000
    return round(kwh * CCF_AWS_PUE * intensity_kg_per_kwh, 4)


def compute_greenops_impact(
    finding: Finding, infra: dict, pricing: dict, carbon: dict, thresholds: dict
) -> Finding:
    # Energy/CO2 formulas follow the Cloud Carbon Footprint open-source
    # methodology (cloudcarbonfootprint.org), an industry-standard approach
    # used by commercial carbon accounting tools. AWS-specific coefficients
    # (Min/Max Watts, PUE) are CCF's published averages across AWS instance
    # microarchitectures.
    resource = next(
        (r for r in infra["resources"] if r["id"] == finding.affected_node), None
    )
    if not resource:
        return finding

    instance_type = resource.get("instance_type")
    region = resource.get("region", "ap-southeast-1")
    hourly_rate = pricing.get(instance_type, 0)
    intensity = carbon.get(region, 0.415)

    cpu_pct = resource.get("cpu_avg_7d", 100)
    utilization = cpu_pct / 100

    if resource.get("type") == "ebs_volume":
        size_gb = resource.get("size_gb", 0)
        monthly_cost = round(size_gb * EBS_COST_PER_GB_MONTH, 2)
        kg_co2 = _compute_ebs_co2(size_gb, intensity)
    else:
        monthly_cost = round(hourly_rate * HOURS_PER_MONTH, 2)
        vcpus = VCPU_MAP.get(instance_type, 4)
        kg_co2 = _compute_instance_co2(vcpus, utilization, intensity)

    if cpu_pct < thresholds["cpu_utilization_pct_max"]:
        idle_ratio = max(0, (thresholds["cpu_utilization_pct_max"] - cpu_pct) / 100)
    else:
        idle_ratio = max(0, 1 - utilization)
    wasted_cost = round(monthly_cost * max(0.5, idle_ratio), 2)

    if finding.recommended_action in FULL_REMOVAL_ACTIONS:
        savings = monthly_cost
        co2_reduction = kg_co2
    elif finding.recommended_action == "resize_down":
        target_hourly = pricing.get("t3.large", 0.0832)
        savings = round((hourly_rate - target_hourly) * HOURS_PER_MONTH, 2) if hourly_rate > target_hourly else 0.0
        target_vcpus = VCPU_MAP.get("t3.large", 2)
        target_co2 = _compute_instance_co2(target_vcpus, utilization, intensity)
        co2_reduction = round(kg_co2 - target_co2, 4) if kg_co2 > target_co2 else 0.0
    else:
        savings = 0.0
        co2_reduction = 0.0

    finding.quantified_impact = {
        "monthly_cost_usd": monthly_cost,
        "wasted_cost_usd": wasted_cost,
        "resize_savings_usd_month": savings,
        "kg_co2_per_month": round(co2_reduction, 4),
        "region_carbon_intensity": intensity,
    }
    return finding


def run_greenops_agent(
    infrastructure: dict,
    logs_summary: str,
    pricing: dict,
    carbon: dict,
    thresholds: dict,
) -> list[Finding]:
    try:
        llm = ChatOpenAI(
            model=os.environ.get("GRAFILAB_MODEL", "gemini/gemini-3.1-flash-lite-preview"),
            temperature=0,
            openai_api_key=os.environ["GRAFILAB_API_KEY"],
            openai_api_base=os.environ.get(
                "GRAFILAB_BASE_URL",
                "https://console-api.grafilab.ai/api/oai/v1/models",
            ),
        )
        structured_llm = llm.with_structured_output(GreenOpsOutput)

        resource_ids = [r["id"] for r in infrastructure["resources"]]
        user_msg = (
            f"## Infrastructure Data\n```json\n{json.dumps(infrastructure, indent=2)}\n```\n\n"
            f"## Valid Resource IDs\n{json.dumps(resource_ids)}\n\n"
            f"## Recent Logs\n{logs_summary}"
        )

        result = structured_llm.invoke(
            [
                {"role": "system", "content": GREENOPS_SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ]
        )
        console.print(
            f"[green]GreenOps agent produced {len(result.findings)} findings.[/green]"
        )

        enriched = []
        for f in result.findings:
            f = compute_greenops_impact(f, infrastructure, pricing, carbon, thresholds)
            enriched.append(f)
        return enriched
    except Exception as exc:
        console.print(f"[red]GreenOps agent failed: {exc}[/red]")
        return [
            Finding(
                agent_source="greenops",
                severity="low",
                confidence=0.0,
                affected_node=infrastructure["resources"][0]["id"],
                description=f"Agent call failed — manual review required. Error: {exc}",
                plain_english="The sustainability analysis agent encountered an error. Manual review is required.",
                recommended_action="flag_for_review",
                evidence_path=[],
                quantified_impact={"monthly_cost_usd": 0, "wasted_cost_usd": 0, "resize_savings_usd_month": 0, "kg_co2_per_month": 0, "region_carbon_intensity": 0},
            )
        ]

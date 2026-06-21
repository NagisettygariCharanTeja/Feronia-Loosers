import json
import os

from langchain_openai import ChatOpenAI
from pydantic import BaseModel
from rich.console import Console

from schemas.models import Finding
from schemas.graph_conventions import NODE_ATTACHED_ACTIONS, IAM_ROLE

console = Console()


def compute_iam_privesc_paths(role_node: dict, privesc_combos: dict) -> list[dict]:
    """
    Pure-Python, no LLM. Checks a role's granted actions against known
    dangerous permission combinations. Returns the list of matched combo
    dicts (id + description), or an empty list if none match.
    """
    granted = set(role_node.get(NODE_ATTACHED_ACTIONS, []))
    matches = []
    for combo in privesc_combos["dangerous_permission_combos"]:
        if set(combo["requires_all"]).issubset(granted):
            matches.append(combo)
    return matches

SECOPS_SYSTEM_PROMPT = """You are a cloud security analyst for Hilti, a construction technology company.
Analyse the provided AWS infrastructure graph and logs using CIS AWS Foundations
Benchmark v2.0 and v3.0 rules. Map severity using CVSS v3.1 base score ranges.

CRITICAL rules to check:
- CIS 1.16: IAM policies must not allow full "*" administrative privileges
- CIS 2.1.1: S3 buckets must not allow public read/write
- CIS 2.2.1: EBS volumes must be encrypted
- CIS 4.1: No security group allows ingress from 0.0.0.0/0 on port 22
- CIS 4.2: No security group allows ingress from 0.0.0.0/0 on port 3389
- CIS 4.3: RDS databases must not be publicly accessible
- CIS 2.3.1: RDS encryption must be enabled
- CIS 5.6/5.7 (v3.0+): EC2 instances must enforce IMDSv2 (http_tokens must be "required", not "optional")
- IAM-PRIVESC (not an official CIS control): IAM identity has a permission combination enabling privilege escalation

For each finding, provide:
- The exact resource ID (MUST exist in the infrastructure data provided — do not invent IDs)
- CVSS-based severity: critical (9+), high (7-8.9), medium (4-6.9), low (0.1-3.9)
- A confidence score 0.0-1.0
- evidence_path: ordered list of resource IDs showing the attack chain.
  EXCEPTION: for findings where recommended_action is "flag_privesc_path",
  evidence_path must contain ONLY the specific IAM permission strings that
  enable the privilege escalation (e.g. ["iam:PassRole", "lambda:CreateFunction"])
  — never the role's own ARN or any other resource ID. For all other finding
  types, evidence_path continues to mean resource IDs as before.
- recommended_action: MUST be one of these exact values only:
  tag_resource, resize_down, resize_up, flag_for_review, create_snapshot,
  enable_encryption, restrict_security_group, rotate_credentials, disable_public_access,
  terminate_instance, delete_volume, delete_database, revoke_all_access,
  delete_iam_role, force_stop, enforce_imdsv2, flag_privesc_path
- plain_english: one or two sentences a non-technical manager can understand
- cis_rule: e.g. "CIS 4.1", "CIS 5.6", or "IAM-PRIVESC" for privilege escalation findings
- mitre_technique: e.g. "T1190", "T1552.005" (for IMDS credential theft), "T1078"

CRITICAL: Only reference resource IDs that appear in the infrastructure data.
Never invent or guess resource IDs. Set agent_source to "secops" for all findings."""


class SecOpsOutput(BaseModel):
    findings: list[Finding]


def run_secops_agent(infrastructure: dict, logs_summary: str, privesc_combos: dict | None = None) -> list[Finding]:
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
        structured_llm = llm.with_structured_output(SecOpsOutput)

        resource_ids = [r["id"] for r in infrastructure["resources"]]
        user_msg = (
            f"## Infrastructure Data\n```json\n{json.dumps(infrastructure, indent=2)}\n```\n\n"
            f"## Valid Resource IDs\n{json.dumps(resource_ids)}\n\n"
            f"## Recent Logs\n{logs_summary}"
        )

        result = structured_llm.invoke(
            [
                {"role": "system", "content": SECOPS_SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ]
        )
        findings = list(result.findings)

        if privesc_combos:
            for resource in infrastructure["resources"]:
                if resource.get("type") != IAM_ROLE:
                    continue
                matches = compute_iam_privesc_paths(resource, privesc_combos)
                for combo in matches:
                    findings.append(Finding(
                        agent_source="secops",
                        severity="critical",
                        confidence=1.0,
                        affected_node=resource["id"],
                        description=f"Privilege escalation path: {combo['id']} — {combo['description']}",
                        plain_english=f"This role has permissions that could allow an attacker to escalate privileges: {combo['description']}",
                        recommended_action="flag_privesc_path",
                        evidence_path=combo["requires_all"],
                        cis_rule="IAM-PRIVESC",
                        mitre_technique="T1078",
                    ))
        console.print(f"[yellow]SecOps agent produced {len(findings)} findings.[/yellow]")
        return findings
    except Exception as exc:
        console.print(f"[red]SecOps agent failed: {exc}[/red]")
        return [
            Finding(
                agent_source="secops",
                severity="low",
                confidence=0.0,
                affected_node=infrastructure["resources"][0]["id"],
                description=f"Agent call failed — manual review required. Error: {exc}",
                plain_english="The security analysis agent encountered an error. Manual review is required.",
                recommended_action="flag_for_review",
                evidence_path=[],
            )
        ]

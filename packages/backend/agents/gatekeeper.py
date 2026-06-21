import json
from pathlib import Path
from typing import Optional

from rich.console import Console

from schemas.models import Finding, ALL_VALID_ACTIONS
from schemas.graph_conventions import NODE_ATTACHED_ACTIONS, ACTION_VALID_NODE_TYPES

console = Console()
MAX_RETRIES = 3


def validate_finding(
    finding: Finding, nx_graph, infrastructure: dict, retry_count: dict[str, int]
) -> tuple[bool, list[str]]:
    errors = []

    if finding.recommended_action not in ALL_VALID_ACTIONS:
        errors.append(
            f"Unrecognised action '{finding.recommended_action}' "
            f"— not in SafeAction or DestructiveAction enum. Possible hallucination."
        )

    if finding.affected_node not in nx_graph.nodes:
        errors.append(
            f"Referenced resource '{finding.affected_node}' not found in "
            f"NetworkX graph — possible hallucination."
        )

    resource_ids = {r["id"] for r in infrastructure["resources"]}
    if finding.affected_node not in resource_ids:
        errors.append(
            f"Referenced resource '{finding.affected_node}' not found in "
            f"infrastructure_state.json — possible hallucination."
        )

    if finding.agent_source == "greenops" and not finding.quantified_impact:
        errors.append(
            "GreenOps finding missing quantified_impact — computation may have failed."
        )

    valid_types = ACTION_VALID_NODE_TYPES.get(finding.recommended_action)
    if valid_types is not None:
        resource = next(
            (r for r in infrastructure["resources"] if r["id"] == finding.affected_node),
            None,
        )
        if resource and resource.get("type") not in valid_types:
            errors.append(
                f"Action '{finding.recommended_action}' not valid for node type "
                f"'{resource.get('type')}' — possible hallucination."
            )

    if finding.recommended_action == "flag_privesc_path":
        resource = next(
            (r for r in infrastructure["resources"] if r["id"] == finding.affected_node),
            None,
        )
        granted = set(resource.get(NODE_ATTACHED_ACTIONS, [])) if resource else set()
        for perm in finding.evidence_path:
            if perm not in granted:
                errors.append(
                    f"Privesc evidence permission '{perm}' not in role's "
                    f"attached_actions — possible hallucination."
                )

    return (len(errors) == 0, errors)


def write_to_manual_review(finding: Finding, errors: list[str]) -> None:
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    with open(output_dir / "manual_review.jsonl", "a") as f:
        entry = {
            "finding": finding.model_dump(mode="json"),
            "errors": errors,
        }
        f.write(json.dumps(entry, default=str) + "\n")
    console.print(
        f"[red]Finding {finding.finding_id} sent to manual review: {errors}[/red]"
    )


def process_with_retry(
    finding: Finding,
    nx_graph,
    infrastructure: dict,
    retry_count: dict[str, int],
) -> tuple[Optional[Finding], bool]:
    fid = finding.finding_id
    retry_count.setdefault(fid, 0)

    passed, errors = validate_finding(finding, nx_graph, infrastructure, retry_count)
    if passed:
        return finding, True

    retry_count[fid] += 1
    if retry_count[fid] >= MAX_RETRIES:
        write_to_manual_review(finding, errors)
        return None, False

    return None, False


def run_gatekeeper(
    findings: list[Finding], nx_graph, infrastructure: dict
) -> tuple[list[Finding], list[dict], dict[str, int]]:
    validated = []
    gatekeeper_errors = []
    retry_count: dict[str, int] = {}

    for finding in findings:
        result, passed = process_with_retry(
            finding, nx_graph, infrastructure, retry_count
        )
        if passed and result is not None:
            validated.append(result)
        elif not passed:
            _, errors = validate_finding(
                finding, nx_graph, infrastructure, retry_count
            )
            gatekeeper_errors.append(
                {"finding_id": finding.finding_id, "errors": errors}
            )

    console.print(
        f"[bold]Gatekeeper:[/bold] {len(validated)}/{len(findings)} findings validated. "
        f"{len(gatekeeper_errors)} rejected."
    )
    return validated, gatekeeper_errors, retry_count

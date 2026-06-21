import json
import os
import sys
from pathlib import Path
import boto3
from botocore.exceptions import BotoCoreError, ClientError

from dotenv import load_dotenv
from langgraph.types import Command
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

load_dotenv()

sys.path.insert(0, str(Path(__file__).parent))

from graph.workflow import build_graph_workflow
from schemas.models import ActionPlanStep
from aws_scanner import scan_infrastructure

console = Console()
DATA_DIR = Path("data")
OUTPUT_DIR = Path("output")


def has_valid_aws_credentials() -> bool:
    try:
        profile = os.getenv("AWS_SCANNER_PROFILE")
        session = boto3.Session(profile_name=profile)
        sts = session.client("sts")
        sts.get_caller_identity()
        return True
    except (BotoCoreError, ClientError, ValueError):
        return False


def load_data():
    raw_logs = json.loads((DATA_DIR / "mock_logs.json").read_text())
    
    if not has_valid_aws_credentials():
        console.print("[bold red]AWS credentials not found or invalid. Cannot scan live infrastructure.[/bold red]")
        raise RuntimeError("AWS credentials required for scanning infrastructure.")

    console.print("[bold green]AWS credentials found! Scanning live infrastructure...[/bold green]")
    infrastructure = scan_infrastructure(region="ap-southeast-1")
        
    return raw_logs, infrastructure


def print_hitl_prompt(pending: list[ActionPlanStep]):
    console.print()
    console.print(
        Panel("[bold red]HUMAN-IN-THE-LOOP APPROVAL REQUIRED[/bold red]", expand=False)
    )
    table = Table(title="Destructive Actions Pending Approval")
    table.add_column("Step", style="bold")
    table.add_column("Action", style="red")
    table.add_column("Target")
    table.add_column("Justification")

    for action in pending:
        if isinstance(action, dict):
            table.add_row(
                str(action["step"]),
                action["action"],
                action["target_node"],
                action["justification"],
            )
        else:
            table.add_row(
                str(action.step),
                action.action,
                action.target_node,
                action.justification,
            )
    console.print(table)
    console.print()


def write_dashboard_json(state: dict):
    OUTPUT_DIR.mkdir(exist_ok=True)
    findings = state.get("validated_findings", [])
    action_plan = state.get("action_plan", [])
    summary = state.get("run_summary", {})

    dashboard = {
        "findings": [
            f.model_dump(mode="json") if hasattr(f, "model_dump") else f
            for f in findings
        ],
        "action_plan": [
            s.model_dump(mode="json") if hasattr(s, "model_dump") else s
            for s in action_plan
        ],
        "summary": summary,
    }
    with open(OUTPUT_DIR / "dashboard.json", "w") as f:
        json.dump(dashboard, f, indent=2, default=str)
    console.print(f"[green]Dashboard written to {OUTPUT_DIR / 'dashboard.json'}[/green]")


def print_run_summary(state: dict):
    summary = state.get("run_summary", {})
    findings = state.get("validated_findings", [])
    action_plan = state.get("action_plan", [])

    console.print()
    console.print(Panel("[bold green]FERONIA RUN SUMMARY[/bold green]", expand=False))
    console.print(f"  Total findings: {len(findings)}")
    console.print(f"  Total action plan steps: {len(action_plan)}")
    console.print(
        f"  Estimated monthly savings: ${summary.get('total_savings_usd_month', 0):.2f}"
    )
    console.print(
        f"  CO2 reduction: {summary.get('total_co2_reduction_kg', 0):.2f} kg/month"
    )
    console.print(f"  HITL decision: {summary.get('hitl_decision', 'n/a')}")
    console.print(
        f"  Gatekeeper rejections: {len(summary.get('gatekeeper_errors', []))}"
    )
    console.print()


def main():
    console.print(
        Panel(
            "[bold cyan]FERONIA — Cloud Security & Sustainability Analysis[/bold cyan]\n"
            "Hilti ImagineHack 2026 — Track 2",
            expand=False,
        )
    )

    raw_logs, infrastructure = load_data()

    initial_state = {
        "raw_logs": raw_logs,
        "standardized_logs": [],
        "infrastructure": infrastructure,
        "router_labels": [],
        "findings": [],
        "validated_findings": [],
        "retry_count": {},
        "gatekeeper_errors": [],
        "action_plan": [],
        "run_summary": {},
        "hitl_decision": None,
        "pending_hitl_actions": [],
    }

    console.print("[bold]Building LangGraph workflow...[/bold]")
    app = build_graph_workflow()
    config = {"configurable": {"thread_id": "feronia-run-001"}}

    console.print("[bold]Starting pipeline...[/bold]")
    result = app.invoke(initial_state, config=config)

    state = app.get_state(config)
    if state.next and "hitl_gate" in state.next:
        pending_raw = state.values.get("pending_hitl_actions", [])
        pending = []
        for item in pending_raw:
            if isinstance(item, ActionPlanStep):
                pending.append(item)
            elif isinstance(item, dict):
                pending.append(ActionPlanStep(**item))

        print_hitl_prompt(pending)
        decision = input("Approve destructive actions? (approve/reject): ").strip()
        if decision not in ("approve", "reject"):
            decision = "reject"
        result = app.invoke(Command(resume=decision), config=config)

    final_state = app.get_state(config).values
    write_dashboard_json(final_state)
    print_run_summary(final_state)


if __name__ == "__main__":
    main()

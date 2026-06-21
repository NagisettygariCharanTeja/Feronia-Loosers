import json
import os
import os
import warnings
from datetime import datetime, timezone
from pathlib import Path
import boto3
from botocore.exceptions import BotoCoreError, ClientError

from langgraph.graph import StateGraph, END
from langgraph.types import Send, interrupt, Command
from langgraph.checkpoint.memory import InMemorySaver
from rich.console import Console

warnings.filterwarnings("ignore", message="Deserializing unregistered type schemas.models")

from schemas.models import FeronaState, Finding, ActionPlanStep
from pipeline.ingestor import ingest_logs
from graph.builder import build_graph, get_graph
from agents.router import route_logs
from agents.secops_agent import run_secops_agent
from agents.greenops_agent import run_greenops_agent
from agents.gatekeeper import run_gatekeeper
from pipeline.synthesizer import synthesize
from execute_aws_actions import execute_real_actions

console = Console()


def _logs_summary(logs) -> str:
    lines = []
    for log in logs:
        if hasattr(log, "model_dump"):
            d = log.model_dump(mode="json")
        else:
            d = log
        lines.append(
            f"- [{d.get('log_type', '?')}] {d.get('resource_id', '?')} "
            f"({d.get('resource_type', '?')}) @ {d.get('event_time', '?')}"
        )
    return "\n".join(lines)


def _graph_summary(nx_graph) -> str:
    return (
        f"Nodes: {nx_graph.number_of_nodes()}, "
        f"Edges: {nx_graph.number_of_edges()}, "
        f"Node types: {set(d.get('type', 'unknown') for _, d in nx_graph.nodes(data=True))}"
    )


def ingest_node(state: FeronaState) -> dict:
    console.print("[bold blue]== Ingest Node ==[/bold blue]")
    valid, corrupted = ingest_logs(state["raw_logs"])
    return {"standardized_logs": valid}


def build_graph_node(state: FeronaState) -> dict:
    console.print("[bold blue]== Build Graph Node ==[/bold blue]")
    g = build_graph(state["infrastructure"])
    console.print(
        f"[cyan]Graph built: {g.number_of_nodes()} nodes, "
        f"{g.number_of_edges()} edges[/cyan]"
    )
    return {}


def router_node(state: FeronaState) -> dict:
    console.print("[bold blue]== Router Node ==[/bold blue]")
    logs_sum = _logs_summary(state["standardized_logs"])
    graph_sum = _graph_summary(get_graph())
    labels = route_logs(logs_sum, graph_sum)
    return {"router_labels": labels}


def secops_node(state: FeronaState) -> dict:
    console.print("[bold blue]== SecOps Agent ==[/bold blue]")
    logs_sum = _logs_summary(state["standardized_logs"])
    data_dir = Path("data")
    privesc_combos = json.loads((data_dir / "iam_privesc_permissions.json").read_text())
    findings = run_secops_agent(state["infrastructure"], logs_sum, privesc_combos)
    return {"findings": findings}


def greenops_node(state: FeronaState) -> dict:
    console.print("[bold blue]== GreenOps Agent ==[/bold blue]")
    logs_sum = _logs_summary(state["standardized_logs"])
    data_dir = Path("data")
    pricing = json.loads((data_dir / "instance_pricing.json").read_text())
    carbon = json.loads((data_dir / "carbon_intensity.json").read_text())
    thresholds = json.loads((data_dir / "zombie_thresholds.json").read_text())
    findings = run_greenops_agent(
        state["infrastructure"], logs_sum, pricing, carbon, thresholds
    )
    return {"findings": findings}


def gatekeeper_node(state: FeronaState) -> dict:
    console.print("[bold blue]== Gatekeeper Node ==[/bold blue]")
    validated, errors, retry_count = run_gatekeeper(
        state["findings"], get_graph(), state["infrastructure"]
    )
    return {
        "validated_findings": validated,
        "gatekeeper_errors": errors,
        "retry_count": retry_count,
    }


def synthesizer_node(state: FeronaState) -> dict:
    console.print("[bold blue]== Synthesizer Node ==[/bold blue]")
    sorted_findings, action_plan = synthesize(state["validated_findings"])
    destructive = [s for s in action_plan if s.requires_approval]
    return {
        "validated_findings": sorted_findings,
        "action_plan": action_plan,
        "pending_hitl_actions": destructive,
    }


def check_hitl_needed(state: FeronaState):
    destructive = [s for s in state["action_plan"] if s.requires_approval]
    if destructive:
        return "hitl_gate"
    return "execute_actions"


def hitl_node(state: FeronaState) -> dict:
    destructive_actions = [s for s in state["action_plan"] if s.requires_approval]
    if not destructive_actions:
        return {"hitl_decision": "auto_approved"}

    decision = interrupt(
        {
            "message": "The following destructive actions require your approval:",
            "pending_actions": [a.model_dump(mode="json") for a in destructive_actions],
        }
    )
    return {"hitl_decision": decision}


def execute_node(state: FeronaState) -> dict:
    console.print("[bold blue]== Execute Actions ==[/bold blue]")
    decision_obj = state.get("hitl_decision", "auto_approved")
    action_plan = list(state["action_plan"])

    approved = []
    
    if isinstance(decision_obj, dict):
        # Per-item approval logic
        finding_id = decision_obj.get("finding_id")
        decision = decision_obj.get("decision")
        
        target_action = next((a for a in action_plan if getattr(a, "finding_id", None) == finding_id), None)
        if target_action:
            target_action.requires_approval = False
            if decision == "approve":
                approved.append(target_action)
            else:
                console.print(f"[yellow]Action for {finding_id} rejected by user.[/yellow]")
    else:
        # Legacy global approval or auto_approved logic
        if decision_obj == "reject":
            console.print("[yellow]Actions rejected by user.[/yellow]")
            approved = [s for s in action_plan if not s.requires_approval]
        else:
            approved = list(action_plan)
        
        # Mark all as processed
        for a in action_plan:
            a.requires_approval = False

    # Prevent re-executing safe actions if we are just processing a single HITL item
    # We will only execute safe actions if this is a legacy global approve/reject 
    # OR if we explicitly added them to `approved`.
    # Actually, we shouldn't execute auto-approved actions every time we loop.
    # To fix this simply, we will ONLY execute actions that are explicitly in `approved`.
    # And if this is a per-item loop, `approved` only contains the single item.
    
    if not approved:
        return {"action_plan": action_plan, "pending_hitl_actions": [s for s in action_plan if s.requires_approval]}

    # Require valid AWS credentials
    try:
        profile = os.getenv("AWS_EXECUTOR_PROFILE")
        boto3.Session(profile_name=profile).client("sts").get_caller_identity()
    except (BotoCoreError, ClientError, ValueError) as e:
        console.print(f"[bold red]AWS credentials not found or invalid. Cannot execute mutations.[/bold red]")
        raise RuntimeError(f"AWS credentials required for real mutations: {e}")

    console.print(f"[bold green]Executing {len(approved)} real mutation(s) on AWS...[/bold green]")
    execution_logs = execute_real_actions(approved, state["infrastructure"])

    # Merge execution logs safely
    existing_logs = state.get("run_summary", {}).get("execution_logs", [])
    merged_logs = existing_logs + execution_logs

    return {
        "action_plan": action_plan, 
        "run_summary": {"execution_logs": merged_logs}, 
        "pending_hitl_actions": [s for s in action_plan if s.requires_approval]
    }


def report_node(state: FeronaState) -> dict:
    console.print("[bold blue]== Final Report ==[/bold blue]")
    findings = state.get("validated_findings", [])
    action_plan = state.get("action_plan", [])
    execution_logs = state.get("run_summary", {}).get("execution_logs", [])

    total_savings = sum(s.savings_usd_month for s in action_plan)
    total_co2 = sum(s.co2_reduction_kg for s in action_plan)

    summary = {
        "total_findings": len(findings),
        "total_actions": len(action_plan),
        "total_savings_usd_month": round(total_savings, 2),
        "total_co2_reduction_kg": round(total_co2, 2),
        "execution_logs": execution_logs,
        "hitl_decision": str(state.get("hitl_decision", "n/a")),
        "gatekeeper_errors": state.get("gatekeeper_errors", []),
    }
    # preserve existing run_summary keys
    final_summary = state.get("run_summary", {}).copy()
    final_summary.update(summary)
    return {"run_summary": final_summary}


def router_fanout(state: FeronaState):
    sends = []
    if "secops" in state["router_labels"]:
        sends.append(Send("secops_agent", state))
    if "greenops" in state["router_labels"]:
        sends.append(Send("greenops_agent", state))
    if not sends:
        sends.append(Send("secops_agent", state))
    return sends


def after_execute_router(state: FeronaState):
    pending = [s for s in state["action_plan"] if s.requires_approval]
    if pending:
        return "hitl_gate"
    return "final_report"


def build_graph_workflow():
    builder = StateGraph(FeronaState)

    builder.add_node("ingest", ingest_node)
    builder.add_node("build_graph", build_graph_node)
    builder.add_node("router", router_node)
    builder.add_node("secops_agent", secops_node)
    builder.add_node("greenops_agent", greenops_node)
    builder.add_node("gatekeeper", gatekeeper_node)
    builder.add_node("synthesizer", synthesizer_node)
    builder.add_node("hitl_gate", hitl_node)
    builder.add_node("execute_actions", execute_node)
    builder.add_node("final_report", report_node)

    builder.set_entry_point("ingest")
    builder.add_edge("ingest", "build_graph")
    builder.add_edge("build_graph", "router")
    builder.add_conditional_edges("router", router_fanout)
    builder.add_edge("secops_agent", "gatekeeper")
    builder.add_edge("greenops_agent", "gatekeeper")
    builder.add_edge("gatekeeper", "synthesizer")
    
    # After synthesizer, check if we need HITL
    builder.add_conditional_edges(
        "synthesizer",
        check_hitl_needed,
        {"hitl_gate": "hitl_gate", "execute_actions": "execute_actions"},
    )
    builder.add_edge("hitl_gate", "execute_actions")
    
    # After executing, loop back to HITL if there are still pending items
    builder.add_conditional_edges(
        "execute_actions", 
        after_execute_router,
        {"hitl_gate": "hitl_gate", "final_report": "final_report"}
    )
    builder.add_edge("final_report", END)

    checkpointer = InMemorySaver()
    return builder.compile(checkpointer=checkpointer, interrupt_before=["hitl_gate"])

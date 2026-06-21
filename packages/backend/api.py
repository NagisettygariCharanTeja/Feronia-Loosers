import json
import asyncio
from pathlib import Path
import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from langgraph.types import Command # pyrefly: ignore

# Auto-inject AWS credentials file on Railway
aws_creds_content = os.environ.get("AWS_CREDENTIALS_FILE_CONTENT")
if aws_creds_content:
    aws_dir = Path.home() / ".aws"
    aws_dir.mkdir(parents=True, exist_ok=True)
    creds_file = aws_dir / "credentials"
    creds_file.write_text(aws_creds_content.replace("\\n", "\n"))
    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(creds_file)

import sys
sys.path.insert(0, str(Path(__file__).parent))

from main import load_data, write_dashboard_json, has_valid_aws_credentials
from aws_scanner import scan_infrastructure
from graph.workflow import build_graph_workflow

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Feronia API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://feronia-loosers.vercel.app", "*"], # Specific domain and fallback
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
DATA_DIR = Path(__file__).parent / "data"
OUTPUT_DIR = Path(__file__).parent / "output"

ACTIVE_RUN = {
    "graph": None,
    "config": None,
    "status": "idle",
    "pending_actions": [],
}

@app.on_event("startup")
async def clear_previous_scan_data():
    dashboard_file = OUTPUT_DIR / "dashboard.json"
    if dashboard_file.exists():
        dashboard_file.unlink()


def _serialise_dashboard(state: dict, status: str = "complete") -> dict:
    findings = state.get("validated_findings", [])
    action_plan = state.get("action_plan", [])
    summary = state.get("run_summary", {}) or {}
    pending = state.get("pending_hitl_actions", []) or []

    summary = {
        **summary,
        "pipeline_status": status,
        "pending_hitl_actions": [
            a.model_dump(mode="json") if hasattr(a, "model_dump") else a
            for a in pending
        ],
    }

    return {
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


def _write_dashboard_snapshot(state: dict, status: str = "complete") -> dict:
    OUTPUT_DIR.mkdir(exist_ok=True)
    dashboard = _serialise_dashboard(state, status=status)
    (OUTPUT_DIR / "dashboard.json").write_text(json.dumps(dashboard, indent=2, default=str))
    return dashboard


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/dashboard")
def get_dashboard():
    if ACTIVE_RUN["graph"] is not None and ACTIVE_RUN["config"] is not None:
        graph = ACTIVE_RUN["graph"]
        state = graph.get_state(ACTIVE_RUN["config"])
        if state.values:
            return _serialise_dashboard(state.values, status=ACTIVE_RUN["status"])

    dashboard_file = OUTPUT_DIR / "dashboard.json"
    if dashboard_file.exists():
        return json.loads(dashboard_file.read_text())
    return {"findings": [], "action_plan": [], "summary": {}}


@app.get("/api/infrastructure")
def get_infrastructure():
    if not has_valid_aws_credentials():
        raise HTTPException(status_code=401, detail="AWS credentials required for scanning infrastructure.")
        
    if ACTIVE_RUN.get("graph") is not None and ACTIVE_RUN.get("config") is not None:
        graph = ACTIVE_RUN["graph"]
        state = graph.get_state(ACTIVE_RUN["config"])
        if state.values and "infrastructure" in state.values:
            return state.values["infrastructure"]
            
    return {"resources": [], "relationships": []}


@app.post("/api/pipeline/schedule")
async def schedule_pipeline(request: Request):
    data = await request.json()
    return {"status": "success", "mode": data.get("mode")}


async def run_pipeline_generator():
    ACTIVE_RUN.update({
        "graph": None,
        "config": None,
        "status": "running",
        "pending_actions": [],
    })

    # Yield immediately to keep the Vercel/proxy connection alive
    yield f"data: {json.dumps({'status': 'Connecting to AWS...', 'type': 'status', 'node': 'init'})}\n\n"
    await asyncio.sleep(0.1)

    try:
        raw_logs, infrastructure = await asyncio.to_thread(load_data)
    except Exception as e:
        yield f"data: {json.dumps({'status': str(e), 'type': 'error', 'node': 'ingest'})}\n\n"
        return

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

    graph = build_graph_workflow()
    config = {"configurable": {"thread_id": "feronia-stream-001"}}
    ACTIVE_RUN.update({"graph": graph, "config": config})

    yield f"data: {json.dumps({'status': 'Pipeline started', 'type': 'status'})}\n\n"
    await asyncio.sleep(0.5)

    for event in graph.stream(initial_state, config=config, stream_mode="updates"):
        for node_name, _node_state in event.items():
            payload = {"status": f"Running {node_name}...", "type": "status", "node": node_name}
            yield f"data: {json.dumps(payload)}\n\n"
            await asyncio.sleep(1.0)

    state = graph.get_state(config)
    if state.next and "hitl_gate" in state.next:
        values = state.values
        pending = [
            a.model_dump(mode="json") if hasattr(a, "model_dump") else a
            for a in values.get("pending_hitl_actions", [])
        ]
        ACTIVE_RUN.update({"status": "approval_required", "pending_actions": pending})
        _write_dashboard_snapshot(values, status="approval_required")
        payload = {
            "status": "approval_required",
            "type": "approval_required",
            "pending_actions": pending,
        }
        yield f"data: {json.dumps(payload)}\n\n"
        return

    final_state = graph.get_state(config).values
    write_dashboard_json(final_state)
    ACTIVE_RUN.update({"status": "complete", "pending_actions": []})

    yield f"data: {json.dumps({'status': 'done', 'type': 'done'})}\n\n"


@app.get("/api/pipeline/stream")
async def stream_pipeline():
    return StreamingResponse(
        run_pipeline_generator(), 
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@app.post("/api/pipeline/approve")
async def approve_pipeline(request: Request):
    data = await request.json()
    decision = data.get("decision")
    finding_id = data.get("finding_id")

    if decision not in {"approve", "reject"}:
        raise HTTPException(status_code=400, detail="decision must be 'approve' or 'reject'")

    graph = ACTIVE_RUN.get("graph")
    config = ACTIVE_RUN.get("config")
    if graph is None or config is None:
        raise HTTPException(status_code=409, detail="No active pipeline run is waiting for approval")

    state = graph.get_state(config)
    if not (state.next and "hitl_gate" in state.next):
        raise HTTPException(status_code=409, detail="Active pipeline run is not waiting for approval")

    ACTIVE_RUN["status"] = "resuming"
    resume_payload = {"finding_id": finding_id, "decision": decision} if finding_id else decision
    for _event in graph.stream(Command(resume=resume_payload), config=config, stream_mode="updates"):
        pass

    final_state = graph.get_state(config).values
    write_dashboard_json(final_state)
    ACTIVE_RUN.update({"status": "complete", "pending_actions": []})
    return {"status": "complete", "decision": decision, "dashboard": _serialise_dashboard(final_state)}


if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
else:
    @app.get("/")
    def root():
        return {"status": "Backend is running. API endpoints are available under /api"}

# CONTEXT.md — Feronia Project

## 1. Project Overview

Feronia is a cloud security and sustainability analysis platform built for **Hilti's ImagineHack 2026 hackathon** (Track 2) at Taylor's University. It ingests mock AWS infrastructure logs, builds a relationship graph of cloud resources, and runs two parallel AI agents — **SecOps** (security) and **GreenOps** (cost + carbon) — to identify vulnerabilities, waste, and carbon-reduction opportunities across a construction technology company's cloud estate.

Feronia optimises across three domains:

1. **Security** — CIS AWS Foundations Benchmark v2.0 + v3.0 violations (including IMDSv2 enforcement), IAM privilege-escalation path detection, MITRE ATT&CK technique mapping, CVSS severity scoring
2. **Cost** — Zombie resource detection, right-sizing overprovisioned instances, wasted spend quantification
3. **Carbon** — Regional carbon intensity analysis, CO2 emissions per workload, migration recommendations to lower-carbon regions

**Architecture summary:** Raw AWS logs are standardised by an ingestor, a NetworkX DiGraph is built from infrastructure state, an LLM-based router classifies the batch, LangGraph fans out to SecOps and GreenOps agents running in parallel, a pure-Python Gatekeeper validates all findings against the graph, a synthesizer deduplicates and sorts findings deterministically, a human-in-the-loop gate pauses for destructive action approval, and an execution simulator applies approved changes. All LLM calls use Grafilab's OpenAI-compatible API with `langchain_openai.ChatOpenAI`.

---

## 2. Folder Structure

```
Feronia/
├── main.py                          — CLI entry point, runs full LangGraph pipeline with HITL approval
├── api.py                           — FastAPI server (stub, /health endpoint only)
├── requirements.txt                 — Python dependencies (langgraph, langchain-openai, networkx, etc.)
├── .env.example                     — Template for environment variables
├── test_run.sh                      — End-to-end test + pipeline execution script
├── CONTEXT.md                       — This file: single source of truth for the codebase
├── schemas/
│   ├── __init__.py                  — Empty package init
│   ├── models.py                    — All Pydantic models, enums, and LangGraph state TypedDict
│   └── graph_conventions.py         — Canonical node/edge attribute name constants
├── data/
│   ├── infrastructure_state.json    — Mock AWS resources (8 nodes) with deliberate problems
│   ├── mock_logs.json               — 10 log entries (9 valid + 1 deliberately malformed)
│   ├── instance_pricing.json        — $/hour by AWS instance type
│   ├── carbon_intensity.json        — gCO2eq/kWh by AWS region (illustrative mock values)
│   ├── zombie_thresholds.json       — Numeric thresholds for idle/zombie resource detection
│   └── iam_privesc_permissions.json — Dangerous IAM permission combinations for privesc detection
├── agents/
│   ├── __init__.py                  — Empty package init
│   ├── router.py                    — LLM-based router: classifies log batch as secops/greenops/both
│   ├── secops_agent.py              — LLM-based security analyst (CIS v2.0+v3.0, MITRE mapping, privesc detection)
│   ├── greenops_agent.py            — LLM-based cost/carbon analyst + pure-Python impact calculator
│   └── gatekeeper.py                — Pure-Python validator (zero LLM calls), retry logic, manual review
├── graph/
│   ├── __init__.py                  — Empty package init
│   ├── builder.py                   — Builds NetworkX DiGraph from infrastructure_state.json
│   └── workflow.py                  — LangGraph StateGraph assembly, all node functions, edge wiring
├── pipeline/
│   ├── __init__.py                  — Empty package init
│   ├── ingestor.py                  — Log standardisation + dead-letter handling
│   └── synthesizer.py               — Merge, deduplicate, deterministic sort, action plan generation
├── output/                          — Created at runtime (gitignored except .gitkeep)
│   ├── .gitkeep                     — Keeps directory in git
│   ├── dashboard.json               — Full pipeline results (written by main.py)
│   ├── corrupted_logs.jsonl         — Malformed log entries (written by ingestor.py)
│   └── manual_review.jsonl          — Findings that failed Gatekeeper validation (written by gatekeeper.py)
└── tests/
    ├── __init__.py                  — Empty package init
    ├── test_gatekeeper.py           — Gatekeeper validation tests (4 tests)
    ├── test_greenops_calc.py        — GreenOps impact calculation tests (3 tests)
    ├── test_synthesizer_sort.py     — Synthesizer sort determinism tests (3 tests)
    ├── test_secops_privesc.py        — IMDSv2 + IAM privesc detection tests (4 tests)
    └── test_end_to_end.py           — Integration tests with mock findings (4 tests)
```

---

## 3. File-by-File Reference

### schemas/models.py

- **Purpose:** Defines all Pydantic models, enums, and the LangGraph state TypedDict used throughout the project.
- **Key classes/objects:**
  - `SafeAction(str, Enum)` — 11 non-destructive action values (tag_resource, resize_down, ..., enforce_imdsv2, flag_privesc_path)
  - `DestructiveAction(str, Enum)` — 6 destructive action values (terminate_instance, delete_volume, etc.)
  - `ALL_VALID_ACTIONS: set[str]` — Union of all SafeAction and DestructiveAction values
  - `DESTRUCTIVE_ACTIONS: set[str]` — Set of destructive action string values
  - `SAFE_ACTIONS: set[str]` — Set of safe action string values
  - `Finding(BaseModel)` — Core finding model with 14 fields (finding_id, agent_source, severity, confidence, affected_node, affected_edge, description, plain_english, recommended_action, evidence_path, quantified_impact, timestamp, cis_rule, mitre_technique)
  - `StandardizedLog(BaseModel)` — Normalised log model with 7 fields (log_id, log_type, resource_id, resource_type, event_time, payload, region)
  - `ActionPlanStep(BaseModel)` — Execution plan step with 10 fields (step, action, target_node, human_label, justification, action_type, requires_approval, savings_usd_month, co2_reduction_kg, finding_id)
  - `FeronaState(TypedDict)` — LangGraph state with 11 fields; `findings` uses `Annotated[list[Finding], operator.add]` for parallel-write safety
- **Dependencies:** None from other Feronia modules (this is the root dependency).
- **Side effects:** None.

### schemas/graph_conventions.py

- **Purpose:** Defines string constants for NetworkX node and edge attribute names, preventing typo-based bugs from hardcoded strings.
- **Key constants:**
  - Node attributes: `NODE_TYPE`, `NODE_NAME`, `NODE_REGION`, `NODE_INSTANCE_TYPE`, `NODE_PUBLIC_EXPOSURE`, `NODE_TAGS`, `NODE_STATE`, `NODE_CPU_AVG_7D`, `NODE_IMDS_HTTP_TOKENS` ("required"|"optional" for EC2), `NODE_ATTACHED_ACTIONS` (list[str] of granted IAM actions for IAM_ROLE nodes)
  - Edge attributes: `EDGE_RELATION`, `EDGE_PORT`, `EDGE_PROTOCOL`
  - Node type values: `EC2_INSTANCE`, `S3_BUCKET`, `RDS_DATABASE`, `SECURITY_GROUP`, `IAM_ROLE`, `LOAD_BALANCER`, `EBS_VOLUME`
  - Edge relation values: `CONNECTS_TO`, `HAS_PERMISSION`, `ROUTES_TRAFFIC_TO`, `ATTACHED_TO`, `PROTECTS`
  - `ACTION_VALID_NODE_TYPES: dict[str, set[str]]` — maps each action to the set of node types it may target (e.g. `terminate_instance` only valid for `ec2_instance`, `delete_volume` only for `ebs_volume`). Used by Gatekeeper check 6.
- **Dependencies:** None.
- **Side effects:** None.

### pipeline/ingestor.py

- **Purpose:** Standardises raw log dicts into `StandardizedLog` Pydantic objects, catching and segregating malformed entries.
- **Key functions:**
  - `ingest_logs(raw_log_list: list[dict]) -> tuple[list[StandardizedLog], list[dict]]` — Iterates raw log entries, attempts to construct a `StandardizedLog` from each. Catches `ValidationError`, `KeyError`, and `TypeError`. Returns (valid_logs, corrupted_entries). Prints summary via Rich console.
- **Dependencies:** `schemas.models.StandardizedLog`
- **Side effects:** Writes `output/corrupted_logs.jsonl` if any entries fail validation. Creates `output/` directory if it doesn't exist.

### pipeline/synthesizer.py

- **Purpose:** Deduplicates findings, sorts them deterministically, and builds an ordered action plan.
- **Key functions:**
  - `build_human_label(f: Finding) -> str` — Maps a finding's recommended_action to a readable label string combined with the affected node ID. Returns e.g. `"Restrict security group — sg-0xyz789abc"`.
  - `synthesize(findings: list[Finding]) -> tuple[list[Finding], list[ActionPlanStep]]` — Deduplicates by (affected_node, recommended_action) tuple. Sorts by severity descending, confidence descending, affected_node ascending, finding_id ascending. Builds ActionPlanStep list with step numbers, marking destructive actions as `requires_approval=True`.
- **Dependencies:** `schemas.models.Finding`, `schemas.models.ActionPlanStep`, `schemas.models.DESTRUCTIVE_ACTIONS`
- **Side effects:** None.

### graph/builder.py

- **Purpose:** Builds a NetworkX DiGraph from the infrastructure state JSON and stores it as a module-level variable (to avoid LangGraph state serialisation issues with DiGraph).
- **Key functions:**
  - `build_graph(infrastructure: dict) -> nx.DiGraph` — Creates a DiGraph, adds one node per resource (ID as node key, all other fields as attributes), adds edges from the relationships list with relation/port/protocol attributes. Stores result in module-level `_GRAPH`. Returns the graph.
  - `get_graph() -> nx.DiGraph` — Returns the module-level `_GRAPH` variable. Used by workflow nodes that need the graph without reading it from LangGraph state.
- **Dependencies:** `schemas.graph_conventions` (EDGE_RELATION, EDGE_PORT, EDGE_PROTOCOL)
- **Side effects:** Mutates module-level `_GRAPH` global variable.

### graph/workflow.py

- **Purpose:** Assembles the full LangGraph StateGraph — defines all 10 node functions, edge wiring, conditional routing, fan-out, HITL interrupt, and compiles the graph with an InMemorySaver checkpointer.
- **Key functions:**
  - `ingest_node(state) -> dict` — Calls `ingest_logs()`, returns `{"standardized_logs": valid}`.
  - `build_graph_node(state) -> dict` — Calls `build_graph()` to set module-level DiGraph, returns `{}` (empty — DiGraph is NOT stored in state).
  - `router_node(state) -> dict` — Summarises logs and graph, calls `route_logs()`, returns `{"router_labels": labels}`.
  - `secops_node(state) -> dict` — Loads `iam_privesc_permissions.json`, calls `run_secops_agent()` with privesc combos, returns `{"findings": findings}`.
  - `greenops_node(state) -> dict` — Loads pricing/carbon/threshold data, calls `run_greenops_agent()`, returns `{"findings": findings}`.
  - `gatekeeper_node(state) -> dict` — Calls `run_gatekeeper()` with `get_graph()`, returns validated findings, errors, and retry counts.
  - `synthesizer_node(state) -> dict` — Calls `synthesize()`, returns sorted findings, action plan, and pending destructive actions.
  - `hitl_node(state) -> dict` — Calls `interrupt()` with pending destructive actions if any exist, returns `{"hitl_decision": decision}`.
  - `execute_node(state) -> dict` — Applies approved actions to infrastructure dict, writes mutated state back to `data/infrastructure_state.json`, returns execution logs.
  - `report_node(state) -> dict` — Aggregates totals (savings, CO2, counts), returns `{"run_summary": summary}`.
  - `router_fanout(state) -> list[Send]` — Returns `Send("secops_agent", state)` and/or `Send("greenops_agent", state)` based on router labels.
  - `check_hitl_needed(state) -> str` — Returns `"hitl_gate"` if any action requires approval, else `"execute_actions"`.
  - `build_graph_workflow() -> CompiledGraph` — Builds and compiles the full StateGraph with InMemorySaver checkpointer and `interrupt_before=["hitl_gate"]`.
- **Dependencies:** All agent modules, pipeline modules, `graph.builder`, `schemas.models`
- **Side effects:** `execute_node` overwrites `data/infrastructure_state.json` with mutated infrastructure.

### agents/router.py

- **Purpose:** LLM-based triage agent that classifies a log batch as needing secops analysis, greenops analysis, or both.
- **Key classes/functions:**
  - `RouterOutput(BaseModel)` — Pydantic model with `labels: list[Literal["secops", "greenops"]]`.
  - `route_logs(log_summary: str, graph_summary: str) -> list[str]` — Constructs a ChatOpenAI instance (temperature=0), calls `.with_structured_output(RouterOutput)`, returns the labels list. On failure, defaults to `["secops", "greenops"]`.
- **Dependencies:** `langchain_openai.ChatOpenAI`
- **Side effects:** Makes one LLM API call to Grafilab.

### agents/secops_agent.py

- **Purpose:** LLM-based security analyst that identifies CIS v2.0 + v3.0 benchmark violations, maps them to MITRE ATT&CK techniques, and runs deterministic IAM privilege-escalation path detection.
- **Key classes/functions:**
  - `SecOpsOutput(BaseModel)` — Pydantic model with `findings: list[Finding]`.
  - `compute_iam_privesc_paths(role_node: dict, privesc_combos: dict) -> list[dict]` — Pure-Python, no LLM. Checks a role's `attached_actions` against known dangerous permission combinations from `iam_privesc_permissions.json`. Returns list of matched combo dicts (id + description), or empty list.
  - `run_secops_agent(infrastructure: dict, logs_summary: str, privesc_combos: dict | None = None) -> list[Finding]` — Constructs a ChatOpenAI instance (temperature=0), provides infrastructure JSON + valid resource IDs + logs as context, calls `.with_structured_output(SecOpsOutput)`. After LLM returns, runs `compute_iam_privesc_paths()` on every IAM_ROLE node and appends deterministic `flag_privesc_path` findings with confidence=1.0. On failure, returns a single fallback Finding.
- **Dependencies:** `schemas.models.Finding`, `schemas.graph_conventions.NODE_ATTACHED_ACTIONS`, `schemas.graph_conventions.IAM_ROLE`, `langchain_openai.ChatOpenAI`
- **Side effects:** Makes one LLM API call to Grafilab.

### agents/greenops_agent.py

- **Purpose:** LLM-based cost/carbon analyst that identifies zombie resources, right-sizing opportunities, and carbon hotspots, then enriches findings with computed financial and carbon impact.
- **Key classes/functions:**
  - `GreenOpsOutput(BaseModel)` — Pydantic model with `findings: list[Finding]`.
  - `compute_greenops_impact(finding: Finding, infra: dict, pricing: dict, carbon: dict, thresholds: dict) -> Finding` — Pure-Python function (no LLM). Looks up the affected resource, calculates monthly cost (hourly_rate * 730), power draw (vCPUs * 10W), CO2 emissions (power * hours * carbon intensity), wasted cost (monthly cost * idle ratio), and resize savings (difference from t3.large baseline). Populates `finding.quantified_impact` dict with five keys. Returns the enriched finding.
  - `run_greenops_agent(infrastructure: dict, logs_summary: str, pricing: dict, carbon: dict, thresholds: dict) -> list[Finding]` — Constructs ChatOpenAI (temperature=0), gets raw findings via structured output, then runs `compute_greenops_impact()` on each finding. On failure, returns a single fallback Finding with zeroed-out quantified_impact.
- **Dependencies:** `schemas.models.Finding`, `langchain_openai.ChatOpenAI`
- **Side effects:** Makes one LLM API call to Grafilab.

### agents/gatekeeper.py

- **Purpose:** Pure-Python validation layer. Zero LLM calls. Checks findings for schema correctness and referential integrity against the infrastructure graph.
- **Key functions:**
  - `validate_finding(finding: Finding, nx_graph, infrastructure: dict, retry_count: dict[str, int]) -> tuple[bool, list[str]]` — Runs six checks: (1) recommended_action in ALL_VALID_ACTIONS, (2) affected_node in nx_graph.nodes, (3) affected_node in infrastructure resource IDs, (4) greenops findings must have quantified_impact, (5) action must be valid for the node's resource type per ACTION_VALID_NODE_TYPES, (6) flag_privesc_path findings must have evidence_path permissions that exist in the role's attached_actions. Returns (passed, error_messages).
  - `write_to_manual_review(finding: Finding, errors: list[str]) -> None` — Appends finding + errors to `output/manual_review.jsonl`.
  - `process_with_retry(finding, nx_graph, infrastructure, retry_count) -> tuple[Optional[Finding], bool]` — Validates a finding, increments retry count on failure. After MAX_RETRIES (3) failures, writes to manual review and returns (None, False).
  - `run_gatekeeper(findings: list[Finding], nx_graph, infrastructure: dict) -> tuple[list[Finding], list[dict], dict[str, int]]` — Iterates all findings through `process_with_retry()`. Returns (validated_findings, gatekeeper_errors, retry_count).
- **Dependencies:** `schemas.models.Finding`, `schemas.models.ALL_VALID_ACTIONS`, `schemas.graph_conventions.NODE_ATTACHED_ACTIONS`, `schemas.graph_conventions.ACTION_VALID_NODE_TYPES`
- **Side effects:** May write to `output/manual_review.jsonl`. Creates `output/` directory if needed.

### main.py

- **Purpose:** CLI entry point that orchestrates the full pipeline run with interactive HITL approval.
- **Key functions:**
  - `load_data() -> tuple[list[dict], dict]` — Reads `data/mock_logs.json` and `data/infrastructure_state.json`.
  - `print_hitl_prompt(pending: list[ActionPlanStep]) -> None` — Renders a Rich table of destructive actions pending approval.
  - `write_dashboard_json(state: dict) -> None` — Serialises findings, action plan, and summary to `output/dashboard.json`.
  - `print_run_summary(state: dict) -> None` — Prints total findings, actions, savings, CO2 reduction, HITL decision, and gatekeeper rejections.
  - `main() -> None` — Loads data, builds LangGraph workflow, invokes with initial state, checks for HITL interrupt, prompts user for approval, resumes graph, writes dashboard, prints summary.
- **Dependencies:** `graph.workflow.build_graph_workflow`, `schemas.models.ActionPlanStep`, `langgraph.types.Command`
- **Side effects:** Reads data files, writes `output/dashboard.json`, prompts for user input on stdin.

### api.py

- **Purpose:** FastAPI server stub. Currently only exposes a `/health` endpoint.
- **Key functions:**
  - `health() -> dict` — Returns `{"status": "ok"}`.
- **Dependencies:** `fastapi`
- **Side effects:** None.

### tests/test_gatekeeper.py

- **Purpose:** Tests Gatekeeper validation logic with valid and invalid findings.
- **Dependencies:** `schemas.models.Finding`, `agents.gatekeeper.validate_finding`, `graph.builder.build_graph`
- **Side effects:** None (reads data files for test fixtures).

### tests/test_greenops_calc.py

- **Purpose:** Tests `compute_greenops_impact()` calculations for correctness.
- **Dependencies:** `schemas.models.Finding`, `agents.greenops_agent.compute_greenops_impact`
- **Side effects:** None (reads data files for test fixtures).

### tests/test_synthesizer_sort.py

- **Purpose:** Tests deterministic sort ordering in the synthesizer.
- **Dependencies:** `schemas.models.Finding`, `pipeline.synthesizer.synthesize`
- **Side effects:** None.

### tests/test_end_to_end.py

- **Purpose:** Integration tests using mock findings (no LLM calls) covering ingestor, graph builder, gatekeeper, synthesizer, and output file generation.
- **Dependencies:** `schemas.models.Finding`, `pipeline.ingestor.ingest_logs`, `graph.builder.build_graph`, `agents.gatekeeper.run_gatekeeper`, `pipeline.synthesizer.synthesize`
- **Side effects:** Writes `output/dashboard.json` and `output/corrupted_logs.jsonl` during test runs.

---

## 4. Data Flow — End to End

When `python main.py` runs, the following steps execute:

**Step 1: Load data files.** `main.py:load_data()` reads `data/mock_logs.json` (10 raw log entries) and `data/infrastructure_state.json` (8 resources + 5 relationships) into memory.

**Step 2: Build initial state.** An `initial_state` dict is constructed with raw_logs, infrastructure, and empty collections for all other fields.

**Step 3: Compile and invoke LangGraph.** `build_graph_workflow()` compiles the StateGraph with InMemorySaver checkpointer and `interrupt_before=["hitl_gate"]`. The graph is invoked with `thread_id = "feronia-run-001"`.

**Step 4: Ingest logs (ingest_node).** `ingest_logs()` iterates the 10 raw log dicts, constructing `StandardizedLog` objects. 9 succeed; the 1 deliberately malformed entry (missing log_type, resource_id, event_time) is caught and written to `output/corrupted_logs.jsonl`. State is updated with `standardized_logs`.

**Step 5: Build NetworkX graph (build_graph_node).** `build_graph()` constructs a DiGraph with 8 nodes and 5 edges from the infrastructure data. The graph is stored in `graph.builder._GRAPH` (module-level variable). The node returns `{}` — the DiGraph is NOT written to LangGraph state (it is not msgpack-serialisable).

**Step 6: Router LLM call (router_node).** A summary of logs and graph statistics is sent to the LLM. The router classifies the batch — typically as `["secops", "greenops"]` since the mock data contains both security and cost signals. State is updated with `router_labels`.

**Step 7: Parallel fan-out (router_fanout).** `router_fanout()` returns `Send` objects based on `router_labels`. If both labels are present, SecOps and GreenOps agents run concurrently via LangGraph's parallel execution.

**Step 8: SecOps agent (secops_node).** The LLM receives the full infrastructure JSON, valid resource IDs, and log summaries. It produces `Finding` objects for CIS violations (e.g., open SSH port 22, public S3 bucket, IAM AdminAccess, unencrypted RDS). Each finding includes CIS rule ID, MITRE technique, severity, confidence, evidence path, and a plain-English description.

**Step 9: GreenOps agent (greenops_node).** The LLM identifies waste (zombie instances at <10% CPU, overprovisioned m5.4xlarge instances, high-carbon-region workloads). `quantified_impact` is set to null by the LLM, then `compute_greenops_impact()` enriches each finding with calculated monthly cost, wasted cost, resize savings, CO2/month, and carbon intensity.

**Step 10: Gatekeeper validation (gatekeeper_node).** All findings from both agents are validated by `run_gatekeeper()` using `get_graph()` for the NetworkX DiGraph. Four checks per finding: action enum membership, node existence in graph, node existence in infrastructure JSON, and quantified_impact presence for greenops findings. Failed findings are collected as errors; after MAX_RETRIES (3), they go to `output/manual_review.jsonl`.

**Step 11: Synthesizer (synthesizer_node).** `synthesize()` deduplicates by (affected_node, recommended_action), sorts deterministically (severity desc, confidence desc, affected_node asc, finding_id asc), and builds an `ActionPlanStep` for each finding. Destructive steps are flagged as `requires_approval=True`.

**Step 12: HITL gate.** The graph pauses at `interrupt_before=["hitl_gate"]`. Control returns to `main.py`, which checks `state.next` for `"hitl_gate"`. If destructive actions exist, a Rich table is printed and the user is prompted: `Approve destructive actions? (approve/reject):`. The graph is resumed via `app.invoke(Command(resume=decision), config)`.

**Step 13: Execute actions (execute_node).** If approved, all actions are applied; if rejected, only safe actions run. Each action mutates the in-memory infrastructure dict (e.g., resize_down changes instance_type to "t3.large", terminate_instance sets state to "terminated"). The mutated infrastructure is written back to `data/infrastructure_state.json`. Execution logs are returned.

**Step 14: Final report (report_node).** Aggregates total savings, CO2 reduction, finding/action counts, execution logs, HITL decision, and gatekeeper errors into a summary dict.

**Step 15: Write output.** `write_dashboard_json()` serialises findings, action plan, and summary to `output/dashboard.json`. `print_run_summary()` displays the totals in the terminal.

---

## 5. LangGraph Architecture

### State Schema (FeronaState)

| Field | Type | Purpose |
|---|---|---|
| `raw_logs` | `list[dict]` | Raw log entries loaded from mock_logs.json |
| `standardized_logs` | `list[StandardizedLog]` | Validated, normalised log objects after ingest |
| `infrastructure` | `dict` | Full infrastructure state (resources + relationships) |
| `router_labels` | `list[str]` | Router classification: subset of ["secops", "greenops"] |
| `findings` | `Annotated[list[Finding], operator.add]` | Raw findings from agents; uses `operator.add` reducer for parallel fan-out merge. Only written by secops/greenops nodes. |
| `validated_findings` | `list[Finding]` | Gatekeeper-validated findings (no reducer — overwrites). Written by gatekeeper_node, read by synthesizer_node and report_node. |
| `retry_count` | `dict[str, int]` | Gatekeeper retry counts keyed by finding_id |
| `gatekeeper_errors` | `list[dict]` | Validation failures from gatekeeper |
| `action_plan` | `list[ActionPlanStep]` | Ordered execution steps built by synthesizer |
| `run_summary` | `dict` | Final aggregated summary (totals, logs, decision) |
| `hitl_decision` | `Optional[str]` | "approve", "reject", or "auto_approved" |
| `pending_hitl_actions` | `list[ActionPlanStep]` | Destructive actions awaiting human approval |

### Graph Nodes

| Node Name | Function | What It Does |
|---|---|---|
| `ingest` | `ingest_node` | Standardises raw logs, segregates corrupted entries |
| `build_graph` | `build_graph_node` | Builds NetworkX DiGraph, stores as module-level variable |
| `router` | `router_node` | LLM classifies batch as secops/greenops/both |
| `secops_agent` | `secops_node` | LLM identifies CIS violations |
| `greenops_agent` | `greenops_node` | LLM identifies waste, then Python computes impact |
| `gatekeeper` | `gatekeeper_node` | Pure-Python validation of all findings |
| `synthesizer` | `synthesizer_node` | Dedup, sort, build action plan |
| `hitl_gate` | `hitl_node` | Pauses for human approval of destructive actions |
| `execute_actions` | `execute_node` | Simulates AWS mutations on infrastructure JSON |
| `final_report` | `report_node` | Aggregates summary statistics |

### Edge Wiring

```
ingest ──> build_graph ──> router ──┬──> secops_agent ──> gatekeeper
                                    │                        ^
                                    └──> greenops_agent ─────┘
                                                             │
                                                             v
                                              synthesizer ──┬──> hitl_gate ──> execute_actions ──> final_report ──> END
                                                            │                       ^
                                                            └── (no destructive) ───┘
```

The router-to-agents edge uses `router_fanout()` which returns `Send` objects. The synthesizer-to-hitl/execute edge uses `check_hitl_needed()` which returns `"hitl_gate"` or `"execute_actions"`.

### Why nx_graph Is NOT in State

NetworkX `DiGraph` objects are not msgpack-serialisable. Storing them in `FeronaState` causes `TypeError: Type is not msgpack serializable: DiGraph` when LangGraph's InMemorySaver checkpointer attempts serialisation. The solution is the module-level variable pattern:

- `graph/builder.py` stores the DiGraph in `_GRAPH` (module-level) via `build_graph()`
- `build_graph_node()` calls `build_graph()` but returns `{}` — nothing goes into state
- `gatekeeper_node()` and `router_node()` call `get_graph()` to access the DiGraph directly

### Parallel Fan-Out Pattern

```python
def router_fanout(state: FeronaState):
    sends = []
    if "secops" in state["router_labels"]:
        sends.append(Send("secops_agent", state))
    if "greenops" in state["router_labels"]:
        sends.append(Send("greenops_agent", state))
    return sends
```

LangGraph's `Send` API delivers a copy of the state to each target node. Both agents write to `findings` — the `Annotated[list[Finding], operator.add]` reducer on `FeronaState.findings` ensures their results are concatenated rather than overwritten.

### HITL Interrupt/Resume Pattern

The graph is compiled with `interrupt_before=["hitl_gate"]`. When execution reaches the hitl_gate node:

1. LangGraph pauses and returns control to `main.py`
2. `app.get_state(config)` shows `state.next == ("hitl_gate",)`
3. `main.py` displays pending destructive actions and prompts the user
4. The graph is resumed via `app.invoke(Command(resume=decision), config=config)`
5. `hitl_node()` receives the decision via `interrupt()` return value

### Determinism Table

| Component | Deterministic? | Mechanism |
|---|---|---|
| Router dispatch | No (LLM) | temperature=0, structured output |
| Graph fan-out | Yes | Static Send edges based on router labels |
| SecOps/GreenOps LLM analysis | No (LLM) | temperature=0, structured output |
| IAM privesc path detection | Yes | Pure Python set-subset check against known combos |
| GreenOps impact calculation | Yes | Pure Python arithmetic from pricing/carbon data |
| Gatekeeper validation | Yes | Pure Python + Pydantic + set membership checks |
| Synthesizer sort | Yes | Fixed tuple key: (severity_order, -confidence, node, id) |
| HITL routing | Yes | DestructiveAction enum membership check |
| Action execution | Yes | Deterministic dict mutation based on action type |

---

## 6. Schemas Reference

### SafeAction (str, Enum) — 11 values

| Value | Simulated Effect |
|---|---|
| `tag_resource` | Adds `{"reviewed": "true"}` tag to resource |
| `resize_down` | Changes instance_type to `t3.large` |
| `resize_up` | Logged only (no mutation) |
| `flag_for_review` | Logged only (no mutation) |
| `create_snapshot` | Logged only (no mutation) |
| `enable_encryption` | Sets `encryption_enabled: true` |
| `restrict_security_group` | Removes inbound rules with source `0.0.0.0/0` (except port 443) |
| `rotate_credentials` | Logged only (no mutation) |
| `disable_public_access` | Sets `public_exposure: false` |
| `enforce_imdsv2` | Sets `http_tokens: "required"` on the EC2 instance |
| `flag_privesc_path` | Logged only (no mutation) — flags IAM privesc path for human review |

### DestructiveAction (str, Enum) — 6 values

| Value | Simulated Effect |
|---|---|
| `terminate_instance` | Sets `state: "terminated"` |
| `delete_volume` | Sets `state: "deleted"` |
| `delete_database` | Sets `state: "deleted"` |
| `revoke_all_access` | Sets `attached_policies: []` |
| `delete_iam_role` | Sets `state: "deleted"` |
| `force_stop` | Sets `state: "stopped"` |

### Finding (BaseModel)

| Field | Type | Validation | Purpose |
|---|---|---|---|
| `finding_id` | `str` | Default: uuid4() | Unique identifier |
| `agent_source` | `Literal["secops", "greenops"]` | Constrained literal | Which agent produced this finding |
| `severity` | `Literal["low", "medium", "high", "critical"]` | Constrained literal | CVSS-mapped severity level |
| `confidence` | `float` | `ge=0.0, le=1.0` | Agent's confidence in the finding |
| `affected_node` | `str` | Required | Resource ID this finding applies to |
| `affected_edge` | `Optional[tuple[str, str]]` | Optional | Source-target edge tuple if finding is edge-related |
| `description` | `str` | Required | Technical description of the issue |
| `plain_english` | `str` | Required | Non-technical summary for managers |
| `recommended_action` | `str` | Must be in ALL_VALID_ACTIONS (validated by Gatekeeper) | Action to take |
| `evidence_path` | `list[str]` | Required | Ordered list of resource IDs showing attack/waste chain |
| `quantified_impact` | `Optional[dict]` | Required for greenops (validated by Gatekeeper) | Financial/carbon impact numbers |
| `timestamp` | `datetime` | Default: utcnow | When the finding was created |
| `cis_rule` | `Optional[str]` | Optional | CIS benchmark rule ID (e.g. "CIS 4.1") |
| `mitre_technique` | `Optional[str]` | Optional | MITRE ATT&CK technique ID (e.g. "T1190") |

### StandardizedLog (BaseModel)

| Field | Type | Purpose |
|---|---|---|
| `log_id` | `str` (default uuid4) | Unique log entry identifier |
| `log_type` | `Literal["cloudtrail", "config_snapshot", "cloudwatch_metric"]` | Source log type |
| `resource_id` | `str` | AWS resource ID this log refers to |
| `resource_type` | `str` | AWS resource type (ec2_instance, s3_bucket, etc.) |
| `event_time` | `datetime` | When the event occurred |
| `payload` | `dict` | Raw event payload (varies by log type) |
| `region` | `str` | AWS region |

### ActionPlanStep (BaseModel)

| Field | Type | Purpose |
|---|---|---|
| `step` | `int` | Ordinal step number (1-indexed) |
| `action` | `str` | Action to execute (SafeAction or DestructiveAction value) |
| `target_node` | `str` | Resource ID to act on |
| `human_label` | `str` | Readable label, e.g. "Restrict security group — sg-0xyz789abc" |
| `justification` | `str` | plain_english from the source finding |
| `action_type` | `Literal["safe", "destructive"]` | Classification |
| `requires_approval` | `bool` | True for destructive actions |
| `savings_usd_month` | `float` (default 0.0) | Estimated monthly savings from this action |
| `co2_reduction_kg` | `float` (default 0.0) | Estimated monthly CO2 reduction |
| `finding_id` | `str` | ID of the source Finding |

### FeronaState (TypedDict)

All 12 fields documented in section 5 above. Two critical design choices:

1. `findings: Annotated[list[Finding], operator.add]` — the `operator.add` reducer means that when SecOps and GreenOps both return `{"findings": [...]}`, the lists are concatenated rather than one overwriting the other. This is essential for the parallel fan-out pattern. Only secops_node and greenops_node write to this field.

2. `validated_findings: list[Finding]` — a separate field with no reducer (default overwrite semantics). The gatekeeper writes its validated output here, and the synthesizer reads from it. This prevents the reducer from inflating the count when gatekeeper and synthesizer return their filtered/sorted findings.

---

## 7. Agent Prompts & Standards

### Router Agent

**Signals for `secops`:** open ports, IAM policy changes, public exposure, failed auth, unencrypted data, security group modifications.

**Signals for `greenops`:** high-cost instance types, low CPU utilisation, unattached volumes, zombie resources, high-carbon regions.

Returns both labels when the batch contains cross-cutting signals (typical for real infrastructure). Uses `RouterOutput` structured output with `labels: list[Literal["secops", "greenops"]]`. On LLM failure, defaults to both.

### SecOps Agent

**CIS AWS Foundations Benchmark rules checked (v2.0 + v3.0):**

| Rule | Version | Description |
|---|---|---|
| CIS 1.16 | v2.0 | IAM policies must not allow full "\*" administrative privileges |
| CIS 2.1.1 | v2.0 | S3 buckets must not allow public read/write |
| CIS 2.2.1 | v2.0 | EBS volumes must be encrypted |
| CIS 2.3.1 | v2.0 | RDS encryption must be enabled |
| CIS 4.1 | v2.0 | No security group allows ingress from 0.0.0.0/0 on port 22 |
| CIS 4.2 | v2.0 | No security group allows ingress from 0.0.0.0/0 on port 3389 |
| CIS 4.3 | v2.0 | RDS databases must not be publicly accessible |
| CIS 5.6/5.7 | v3.0+ | EC2 instances must enforce IMDSv2 (`http_tokens` must be `"required"`, not `"optional"`) |
| IAM-PRIVESC | Not an official CIS control | IAM identity has a permission combination enabling privilege escalation (based on Rhino Security Labs research / CloudGoat attack scenarios) |

**CVSS v3.1 severity mapping:**
- Critical: CVSS 9.0+
- High: CVSS 7.0–8.9
- Medium: CVSS 4.0–6.9
- Low: CVSS 0.1–3.9

**MITRE ATT&CK usage:** Each finding may include a `mitre_technique` field (e.g. "T1190" for Exploit Public-Facing Application, "T1078" for Valid Accounts). The agent maps CIS violations to their most relevant MITRE technique.

The prompt explicitly lists all 17 valid recommended_action values (including `enforce_imdsv2` and `flag_privesc_path`) and instructs the LLM to only reference resource IDs that exist in the provided infrastructure data.

**Post-LLM deterministic enrichment:** After the LLM returns findings, `run_secops_agent()` runs `compute_iam_privesc_paths()` on every IAM_ROLE node to produce ground-truth privesc findings (confidence=1.0) independently of LLM output. This follows the same "LLM proposes, pure-Python verifies" pattern used by `compute_greenops_impact()` in GreenOps.

### GreenOps Agent

**Three analysis sub-domains:**

1. **Zombie resources** — Instances with `cpu_avg_7d < 10%` for 7+ consecutive days, or unattached EBS volumes (state="available", attached_to=null). Recommended action: `terminate_instance` or `flag_for_review`.

2. **Right-sizing** — Instances where `cpu_avg_7d < 25%` and instance type is larger than t3.large. Recommended action: `resize_down`.

3. **Carbon optimisation** — Workloads running in high-carbon regions (e.g. ap-southeast-1 at 620 gCO2/kWh) that could migrate to lower-carbon alternatives. Recommended action: `tag_resource` or `flag_for_review`.

**Why quantified_impact is computed in Python, not by the LLM:** LLMs are unreliable at arithmetic. The prompt explicitly tells the agent to set `quantified_impact` to null. After the LLM call, `compute_greenops_impact()` runs pure Python against the pricing and carbon intensity tables to produce exact, reproducible numbers. This separation ensures financial and carbon calculations are deterministic and auditable.

### Gatekeeper

**Validation checks (in order):**

1. **Action enum check** — `finding.recommended_action` must be in `ALL_VALID_ACTIONS` (union of SafeAction and DestructiveAction values). Catches LLM hallucinations like invented action names.
2. **Node in NetworkX graph** — `finding.affected_node` must exist in `nx_graph.nodes`. Catches hallucinated resource IDs.
3. **Node in infrastructure JSON** — `finding.affected_node` must exist in the infrastructure resource ID set. Double-checks against source data (belt and suspenders with check 2).
4. **GreenOps impact populated** — If `agent_source == "greenops"`, `quantified_impact` must not be None. Catches failures in `compute_greenops_impact()`.
5. **Action-node-type compatibility** — The `recommended_action` must be valid for the `affected_node`'s resource type, per `ACTION_VALID_NODE_TYPES` (e.g. `terminate_instance` only for `ec2_instance`, `delete_volume` only for `ebs_volume`). Catches LLM mismatches like recommending "terminate_instance" for an EBS volume.
6. **Privesc evidence integrity** — If `recommended_action == "flag_privesc_path"`, every permission string in `evidence_path` must actually appear in the affected role's `attached_actions`. Catches LLM-hallucinated permissions that the role does not actually have.

Findings that fail validation are retried up to MAX_RETRIES (3) times. After exhaustion, they are written to `output/manual_review.jsonl` and excluded from the action plan.

---

## 8. Data Files Reference

### data/infrastructure_state.json

- **Contains:** 8 AWS resources and 5 relationships between them, representing a construction tech company's cloud estate.
- **Loaded by:** `main.py:load_data()`, passed through LangGraph state as `infrastructure`
- **Used by:** `graph/builder.py` (to build NetworkX graph), `agents/secops_agent.py` and `agents/greenops_agent.py` (passed to LLM as context), `agents/gatekeeper.py` (referential integrity checks), `graph/workflow.py:execute_node()` (mutation target)
- **Deliberate problems seeded for agents to find:**
  - `i-0abc123def456`: EC2 at 4.2% CPU (zombie/oversized), publicly exposed, `http_tokens: "optional"` (IMDSv2 not enforced — triggers CIS 5.6/5.7)
  - `i-0zombie999`: c5.2xlarge at 0.8% CPU (zombie), owner=unknown, no IAM profile
  - `sg-0xyz789abc`: Security group with open inbound rules
  - `bim-processor-role`: `attached_actions: ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction", "iam:CreatePolicyVersion"]` — triggers both `iam_privesc_by_passrole_lambda` and `iam_privesc_by_policy_version` combos
  - `vol-0unattached456`: 500GB EBS volume, attached_to=null
  - `rds-hilti-projects-db`: encryption_enabled=false
  - `s3-hilti-bim-models`: No versioning, no encryption
  - `i-0lowutil888`: EC2 at 6.1% CPU (oversized)
  - All resources in ap-southeast-1 (high-carbon region at 620 gCO2/kWh)

### data/mock_logs.json

- **Contains:** 10 log entries: 4 CloudTrail security events, 4 Config snapshots, 1 CloudWatch metric, 1 deliberately malformed entry.
- **Loaded by:** `main.py:load_data()`
- **Used by:** `pipeline/ingestor.py` (standardisation), `agents/router.py` (classification), agent LLM prompts (context)
- **Entry breakdown:**
  1. CloudTrail: AuthorizeSecurityGroupIngress (SSH 0.0.0.0/0 on sg-0xyz789abc)
  2. CloudTrail: PutBucketPolicy (public read on s3-hilti-bim-models)
  3. CloudTrail: AttachRolePolicy (AdministratorAccess on bim-processor-role)
  4. CloudTrail: ConsoleLogin failure (unknown-contractor, no MFA)
  5. Config: i-0abc123def456 snapshot (m5.4xlarge, 4.2% CPU, $560.64/mo)
  6. Config: i-0zombie999 snapshot (c5.2xlarge, 0.8% CPU, $248.20/mo)
  7. Config: vol-0unattached456 snapshot (available, unattached, 500GB)
  8. Config: rds-hilti-projects-db snapshot (unencrypted, publicly accessible)
  9. CloudWatch: i-0lowutil888 CPUUtilization (avg 6.1%, max 12.3%)
  10. Malformed: `{"this_entry_is": "deliberately_malformed"}` — missing log_type, resource_id, event_time

### data/instance_pricing.json

- **Contains:** AWS on-demand hourly rates ($/hour) for 8 instance types.
- **Loaded by:** `graph/workflow.py:greenops_node()` and `tests/test_greenops_calc.py`
- **Used by:** `agents/greenops_agent.py:compute_greenops_impact()` to calculate monthly cost (rate * 730 hours) and resize savings.
- **Values:** Based on approximate AWS on-demand pricing for ap-southeast-1 (Singapore). Not live prices.

### data/carbon_intensity.json

- **Contains:** Grid carbon intensity in gCO2eq/kWh for 7 AWS regions.
- **Loaded by:** `graph/workflow.py:greenops_node()` and `tests/test_greenops_calc.py`
- **Used by:** `agents/greenops_agent.py:compute_greenops_impact()` to calculate CO2 emissions per workload.
- **Values:** Illustrative mock values modelled on Electricity Maps and GHG Protocol Scope 2 methodology. Not live grid data. Notable: ap-southeast-1 (Singapore) = 620, ca-central-1 (Canada) = 120, us-west-2 (Oregon) = 136.

### data/zombie_thresholds.json

- **Contains:** Numeric thresholds for classifying resources as idle/zombie.
- **Loaded by:** `graph/workflow.py:greenops_node()` and `tests/test_greenops_calc.py`
- **Used by:** `agents/greenops_agent.py:compute_greenops_impact()` for idle ratio calculation.
- **Values:** `cpu_utilization_pct_max: 10` (instances below 10% are idle), `consecutive_days_required: 7`, `network_io_bytes_max: 1000`, `unattached_volume_days: 7`.

### data/iam_privesc_permissions.json

- **Contains:** 4 dangerous IAM permission combinations that enable privilege escalation, based on Rhino Security Labs research and CloudGoat attack scenarios.
- **Loaded by:** `graph/workflow.py:secops_node()`
- **Used by:** `agents/secops_agent.py:compute_iam_privesc_paths()` to check each IAM_ROLE's `attached_actions` against known dangerous combos.
- **Combos defined:**
  - `iam_privesc_by_policy_version`: requires `iam:CreatePolicyVersion` — can create a new default policy version granting full access.
  - `iam_privesc_by_rollback`: requires `iam:SetDefaultPolicyVersion` — can roll back to a prior, more permissive policy version.
  - `iam_privesc_by_passrole_lambda`: requires `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` — can pass a privileged role to a new Lambda and invoke it.
  - `iam_privesc_by_attachment`: requires `iam:AttachUserPolicy` — can attach AdministratorAccess to self or another user.

---

## 9. Output Files

### output/dashboard.json

Written by `main.py:write_dashboard_json()` at the end of each pipeline run.

```json
{
  "findings": [
    {
      "finding_id": "uuid",
      "agent_source": "secops|greenops",
      "severity": "critical|high|medium|low",
      "confidence": 0.0-1.0,
      "affected_node": "resource-id",
      "description": "...",
      "plain_english": "...",
      "recommended_action": "action_name",
      "evidence_path": ["id1", "id2"],
      "quantified_impact": {...} | null,
      "timestamp": "ISO8601",
      "cis_rule": "CIS X.Y" | null,
      "mitre_technique": "TXXXX" | null
    }
  ],
  "action_plan": [
    {
      "step": 1,
      "action": "action_name",
      "target_node": "resource-id",
      "human_label": "Readable label — resource-id",
      "justification": "plain english explanation",
      "action_type": "safe|destructive",
      "requires_approval": true|false,
      "savings_usd_month": 0.0,
      "co2_reduction_kg": 0.0,
      "finding_id": "uuid"
    }
  ],
  "summary": {
    "total_findings": N,
    "total_actions": N,
    "total_savings_usd_month": 0.00,
    "total_co2_reduction_kg": 0.00,
    "execution_logs": [...],
    "hitl_decision": "approve|reject|auto_approved",
    "gatekeeper_errors": [...]
  }
}
```

### output/corrupted_logs.jsonl

Written by `pipeline/ingestor.py` when log entries fail StandardizedLog validation. Each line is a JSON object:

```json
{"original": {<raw log entry>}, "error": "<ValidationError or KeyError message>"}
```

Triggered when a raw log dict is missing required fields (log_type, resource_id, resource_type, event_time) or has invalid values for constrained fields.

### output/manual_review.jsonl

Written by `agents/gatekeeper.py:write_to_manual_review()` when a finding fails validation after MAX_RETRIES (3) attempts. Each line is a JSON object:

```json
{"finding": {<Finding model_dump>}, "errors": ["error message 1", "error message 2"]}
```

Triggered by: hallucinated resource IDs, unrecognised action names, missing quantified_impact on greenops findings, fabricated privesc evidence permissions. These findings are excluded from the action plan and require manual human review.

---

## 10. Test Coverage

### tests/test_gatekeeper.py (5 tests, no LLM calls)

| Test Name | What It Proves |
|---|---|
| `test_valid_safe_action_passes` | A finding with a valid SafeAction (`restrict_security_group`) and existing node (`sg-0xyz789abc`) passes validation with zero errors |
| `test_unrecognised_action_fails` | A finding with an invented action (`nuke_from_orbit`) fails with "Unrecognised action" error |
| `test_nonexistent_node_fails` | A finding referencing `i-doesnotexist` fails with "possible hallucination" error |
| `test_valid_node_passes` | A finding referencing a valid node (`i-0abc123def456`) with a valid action (`disable_public_access`) passes |
| `test_gatekeeper_rejects_action_node_type_mismatch` | A finding with `terminate_instance` on an `ebs_volume` node (`vol-0unattached456`) fails with "not valid for node type" error |

### tests/test_greenops_calc.py (3 tests, no LLM calls)

| Test Name | What It Proves |
|---|---|
| `test_monthly_cost_m5_4xlarge` | `compute_greenops_impact()` on an m5.4xlarge fixture produces `monthly_cost_usd` within 0.01 of 560.64 (0.768 * 730) |
| `test_quantified_impact_always_populated` | After calling `compute_greenops_impact()` on a c5.2xlarge fixture, `quantified_impact` is not None and contains `monthly_cost_usd` and `kg_co2_per_month` |
| `test_resize_savings_positive_for_large_instance` | `resize_savings_usd_month` is > 0 when downsizing from m5.4xlarge (0.768/hr) to t3.large (0.0832/hr) |

### tests/test_synthesizer_sort.py (3 tests, no LLM calls)

| Test Name | What It Proves |
|---|---|
| `test_deterministic_sort` | Running `synthesize()` twice on the same input produces identical finding_id ordering |
| `test_critical_before_others` | Critical findings always sort before high, high before medium, medium before low |
| `test_higher_confidence_first_within_severity` | Among same-severity findings, higher confidence values appear first |

### tests/test_secops_privesc.py (4 tests, no LLM calls)

| Test Name | What It Proves |
|---|---|
| `test_imdsv2_finding_triggers_on_optional_tokens` | A finding with `recommended_action="enforce_imdsv2"` on an EC2 node with `http_tokens="optional"` passes Gatekeeper validation |
| `test_privesc_combo_detected_when_permissions_present` | `compute_iam_privesc_paths()` on `bim-processor-role` (with seeded dangerous permissions) returns at least `iam_privesc_by_passrole_lambda` and `iam_privesc_by_policy_version` |
| `test_privesc_combo_not_flagged_when_permissions_absent` | A role with only benign permissions (`s3:GetObject`, `s3:PutObject`) returns an empty list — no false positives |
| `test_gatekeeper_rejects_fabricated_privesc_evidence` | A `flag_privesc_path` finding whose evidence references `ec2:RunInstances` (not in the role's `attached_actions`) fails Gatekeeper check 5 with "possible hallucination" error |

### tests/test_end_to_end.py (4 tests, no LLM calls)

| Test Name | What It Proves |
|---|---|
| `test_ingestor_counts` | Feeding `mock_logs.json` through `ingest_logs()` produces exactly 9 valid logs and 1 corrupted entry; `output/corrupted_logs.jsonl` is created |
| `test_graph_builds_without_crash` | `build_graph()` produces a DiGraph with 8 nodes and 5 edges without errors |
| `test_full_pipeline_mock` | Using mock findings (4 hardcoded Finding objects), the gatekeeper + synthesizer pipeline produces a valid `output/dashboard.json` with `findings`, `action_plan`, and `summary` keys |
| `test_no_hallucinated_nodes_in_action_plan` | Every `target_node` in the action plan exists in `infrastructure_state.json` resource IDs |

---

## 11. Environment Variables

| Variable | Purpose | Valid Values | Default |
|---|---|---|---|
| `GRAFILAB_API_KEY` | API key for Grafilab's OpenAI-compatible endpoint | Any valid Grafilab API key string | None (required) |
| `GRAFILAB_BASE_URL` | Base URL for the LLM API | URL string | `https://console-api.grafilab.ai/api/oai/v1/models` |
| `GRAFILAB_MODEL` | Model identifier to use for LLM calls | Model name string | `gemini/gemini-3.1-flash-lite-preview` |
| `AUTO_APPROVE_SAFE_ACTIONS` | Whether to skip HITL for safe (non-destructive) actions | `true` or `false` | `false` (all actions go through HITL if destructive ones exist) |

All variables are defined in `.env.example`. Copy to `.env` and fill in `GRAFILAB_API_KEY` before running. Loaded by `python-dotenv` at the top of `main.py`.

---

## 12. Known Issues & Future Work

- **msgpack deserialization warnings** — LangGraph's InMemorySaver emits `Deserializing unregistered type schemas.models.StandardizedLog/Finding/ActionPlanStep` warnings because custom Pydantic types are not pre-registered with the msgpack serialiser. Fixed by suppressing these specific warnings via `warnings.filterwarnings("ignore", message="Deserializing unregistered type schemas.models")` in `graph/workflow.py`. InMemorySaver does not accept `allowed_msgpack_modules` as a constructor argument in langgraph 1.2.6.
- **DiGraph not in LangGraph state** — NetworkX DiGraph is not msgpack-serialisable. Worked around via a module-level variable in `graph/builder.py` with `get_graph()` accessor.
- **AUTO_APPROVE_SAFE_ACTIONS=false** means the HITL gate activates whenever any destructive action exists, even though safe actions don't need approval. The `execute_node` already handles this correctly (runs safe actions regardless of decision), but the interrupt still pauses the pipeline.
- **api.py is a stub** — Only has a `/health` endpoint. FastAPI endpoints for triggering pipeline runs, fetching dashboard data, and managing HITL approvals via REST are not yet implemented.
- **Carbon intensity values are mock** — Production would integrate with the Electricity Maps API or WattTime for real-time grid carbon intensity data.
- **AWS integration is live** — `aws_scanner.py` performs real read-only scans via boto3, and `execute_aws_actions.py` performs real mutations. Destructive actions (`terminate_instance`, `delete_volume`, `delete_database`, `delete_iam_role`) are irreversible — use `terraform apply` to recreate destroyed resources.
- **IAM credential scope gap** — Both `aws_scanner.py` and `execute_aws_actions.py` currently run under an AdministratorAccess IAM user (per GUIDE_FOR_BACKEND.md), which is the same anti-pattern that SecOps' CIS 1.16 check flags. Fixing this requires a Terraform-side IAM policy change: a scoped read-only role for the scanner and a scoped write-limited role for the executor. This is out of scope for this codebase change.
- **Reserved Instance / Savings Plan detection** — Not yet implemented. Could compare on-demand spend against RI/SP pricing for committed-use recommendations.
- **Gatekeeper retry loop** — The current retry logic increments the counter but doesn't actually re-invoke the LLM agent to produce a corrected finding. It simply re-validates the same finding, which will always fail the same way. In production, the retry would re-prompt the agent with the validation errors.

---

## 13. How to Run

### Prerequisites

- Python 3.10+
- A Grafilab API key (obtain from Grafilab console)

### Setup

```bash
# Navigate to the project
cd Feronia/

# Create and activate a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # macOS/Linux
# or: venv\Scripts\activate  # Windows

# Install dependencies
python -m pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and set GRAFILAB_API_KEY=your_actual_key
```

### Run Tests (no API key required)

```bash
python -m pytest tests/ -v
```

Expected output: 14 tests pass. Tests use mock findings and do not make LLM calls.

### Run the Full Pipeline (requires API key)

```bash
python main.py
```

Expected output sequence:

1. Banner: "FERONIA — Cloud Security & Sustainability Analysis"
2. "Building LangGraph workflow..."
3. "Starting pipeline..."
4. Ingest node: "Processed 10 logs. 9 succeeded. 1 corrupted"
5. Build graph: "Graph built: 8 nodes, 5 edges"
6. Router: "Router decided: ['secops', 'greenops']"
7. SecOps agent: "SecOps agent produced N findings"
8. GreenOps agent: "GreenOps agent produced N findings"
9. Gatekeeper: "N/M findings validated. K rejected."
10. **HITL prompt** (if destructive actions exist): Table of pending actions
11. User input: `Approve destructive actions? (approve/reject):`
12. Execution: Step-by-step action log
13. "Dashboard written to output/dashboard.json"
14. Summary panel with totals

### Run the End-to-End Script

```bash
bash test_run.sh
```

This runs pip install, pytest, then `echo "approve" | python main.py` (auto-approves), verifies output files, and prints the final dashboard.

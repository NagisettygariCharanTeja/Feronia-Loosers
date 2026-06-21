# Real AWS integration — guide for the backend

Two new modules, both written directly against your CONTEXT.md schemas. Goal: zero changes to
`schemas/`, `graph/builder.py`, `agents/`, `pipeline/synthesizer.py`. The only file that actually
changes is `graph/workflow.py`, in two small places.

## Files

- `aws_scanner.py` — replaces the `infrastructure_state.json` file read. Calls boto3, returns the
  same `{"resources": [...], "relationships": [...]}` shape.
- `execute_aws_actions.py` — replaces `execute_node`'s JSON-mutation body. Same input/output shape,
  real boto3 calls instead.

## Integration steps

**1. Swap the infrastructure source in `main.py`'s `load_data()`:**

```python
# before:
infrastructure = json.load(open("data/infrastructure_state.json"))

# after:
from aws_scanner import scan_infrastructure
infrastructure = scan_infrastructure(region="ap-southeast-1")
```

Logs (`mock_logs.json`) can stay exactly as-is for now — see "What's not covered" below.

**2. Swap the body of `execute_node` in `graph/workflow.py`:**

```python
from execute_aws_actions import execute_real_actions

def execute_node(state: FeronaState) -> dict:
    approved = [s for s in state["action_plan"] if not s.requires_approval or state["hitl_decision"] == "approve"]
    execution_logs = execute_real_actions(approved, state["infrastructure"])
    return {"execution_logs": execution_logs}
```

Adjust the exact filtering logic to match whatever `execute_node` currently does for safe-vs-approved
actions — the point is just that `execute_real_actions()` takes the same step list your current
version does and returns the same log shape, so this should be close to a straight swap.

**3. Credentials.** Both modules call `boto3.client(...)` with no explicit credentials, so they pick
up whatever's in the environment — either `aws configure`'s default profile or
`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` env vars. Use the same IAM user Sour set up for
Terraform; `AdministratorAccess` covers both the scanner's read calls and the executor's write
calls. No extra setup needed if Terraform already ran from this machine.

## Two new privesc combos to know about

The Terraform now triggers **three** of the four combos in `iam_privesc_permissions.json`:
`iam_privesc_by_passrole_lambda` and `iam_privesc_by_policy_version` (via `bim-processor-role`),
plus `iam_privesc_by_attachment` (via the new `jobsite-sync-role`, granted `iam:AttachUserPolicy`).
`compute_iam_privesc_paths()` needs zero changes — it already runs generically against every
`IAM_ROLE` node, so this just falls out of the real scan.

## What's not covered yet (small, known gaps)

1. **`graph_conventions.py` needs two new type constants** if you want the Lambda and DynamoDB
   table to show up as their own graph nodes (`lambda_function`, `dynamodb_table`). Right now
   `aws_scanner.py` only picks up the IAM role attached to the Lambda — which is enough for the
   privesc finding to work — but not the Lambda/DynamoDB resources themselves as nodes. Two-line
   addition, skip it if you don't need those nodes for the demo.

2. **Logs are still mock.** `mock_logs.json` stays as scripted CloudTrail-style events for now —
   pulling real CloudTrail history is a bigger lift (delivery lag, `lookup_events` pagination) and
   genuinely optional; the agents work fine off the real infrastructure scan plus scripted logs.

3. **S3 "encryption_enabled" is never `True` unless someone sets a customer KMS key.** This is an
   AWS platform behavior, not a bug — see the caveat in `aws_scanner.py`'s `_scan_s3_buckets()`.

4. **`enable_encryption` on RDS/EBS doesn't flip a bit in place** — AWS doesn't support that.
   `execute_aws_actions.py` defaults to tagging the resource as flagged-for-encryption rather than
   lying about it being instant. Flip `SIMPLE_ENCRYPTION_MODE = False` only if you've tested the
   real snapshot-copy-restore flow ahead of time — it's slow and creates a new resource ID.

## Before you run this for real

- **Rehearse the full approve flow once before the live demo.** Once `execute_node` is wired to
  `execute_aws_actions`, approving a destructive action (`terminate_instance`, `delete_volume`,
  `delete_database`, `delete_iam_role`) actually destroys real infrastructure, irreversibly. If
  that happens mid-test, `terraform apply` again to bring the resource back before the next run.
- **Run `aws_scanner.py` standalone first** (`python aws_scanner.py` — it has a `__main__` block
  that prints the scanned dict) to sanity-check the output shape before wiring it into the full
  pipeline. Compare resource count against `terraform output all_resource_ids` — should be 8 EC2/SG/IAM/EBS/RDS/S3
  resources plus the `jobsite-sync-role` IAM role (11 total — Lambda/DynamoDB themselves won't
  appear as nodes yet per gap #1 above).
- **Existing tests will need updating.** `test_end_to_end.py`'s `test_graph_builds_without_crash`
  currently asserts `8 nodes, 5 edges` against the mock file — once this is real, that count
  changes (closer to 9 nodes counting the new IAM role, plus whatever edges `_build_relationships`
  produces). Worth a quick pytest run after wiring this in to see what actually comes out and
  update the assertion to match reality rather than the old mock numbers.

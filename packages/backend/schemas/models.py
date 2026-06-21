from enum import Enum
from typing import Annotated, Any, Literal, Optional, TypedDict
from datetime import datetime, timezone
import operator
from pydantic import BaseModel, Field
import uuid


class SafeAction(str, Enum):
    TAG_RESOURCE = "tag_resource"
    RESIZE_DOWN = "resize_down"
    RESIZE_UP = "resize_up"
    FLAG_FOR_REVIEW = "flag_for_review"
    CREATE_SNAPSHOT = "create_snapshot"
    ENABLE_ENCRYPTION = "enable_encryption"
    RESTRICT_SECURITY_GROUP = "restrict_security_group"
    ROTATE_CREDENTIALS = "rotate_credentials"
    DISABLE_PUBLIC_ACCESS = "disable_public_access"
    ENFORCE_IMDSV2 = "enforce_imdsv2"
    # No DestructiveAction for privesc — stripping an IAM permission inferred
    # from an LLM-read policy is high-risk and hard to undo; stays safe/flag-only.
    FLAG_PRIVESC_PATH = "flag_privesc_path"


class DestructiveAction(str, Enum):
    TERMINATE_INSTANCE = "terminate_instance"
    DELETE_VOLUME = "delete_volume"
    DELETE_DATABASE = "delete_database"
    REVOKE_ALL_ACCESS = "revoke_all_access"
    DELETE_IAM_ROLE = "delete_iam_role"
    FORCE_STOP = "force_stop"


ALL_VALID_ACTIONS = {a.value for a in SafeAction} | {a.value for a in DestructiveAction}
DESTRUCTIVE_ACTIONS = {a.value for a in DestructiveAction}
SAFE_ACTIONS = {a.value for a in SafeAction}


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_source: Literal["secops", "greenops"]
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    affected_node: str
    affected_edge: Optional[tuple[str, str]] = None
    description: str
    plain_english: str
    recommended_action: str
    evidence_path: list[str]
    quantified_impact: Optional[dict] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    cis_rule: Optional[str] = None
    mitre_technique: Optional[str] = None


class StandardizedLog(BaseModel):
    log_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    log_type: Literal["cloudtrail", "config_snapshot", "cloudwatch_metric"]
    resource_id: str
    resource_type: str
    event_time: datetime
    payload: dict
    region: str


class ActionPlanStep(BaseModel):
    step: int
    action: str
    target_node: str
    human_label: str
    justification: str
    action_type: Literal["safe", "destructive"]
    requires_approval: bool
    savings_usd_month: float = 0.0
    co2_reduction_kg: float = 0.0
    finding_id: str


class FeronaState(TypedDict):
    raw_logs: list[dict]
    standardized_logs: list[StandardizedLog]
    infrastructure: dict
    router_labels: list[str]
    findings: Annotated[list[Finding], operator.add]
    validated_findings: list[Finding]
    retry_count: dict[str, int]
    gatekeeper_errors: list[dict]
    action_plan: list[ActionPlanStep]
    run_summary: dict
    hitl_decision: Optional[str]
    pending_hitl_actions: list[ActionPlanStep]

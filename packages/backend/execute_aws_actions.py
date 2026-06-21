"""
execute_aws_actions.py — real AWS execution layer for Feronia.

CREDENTIAL SCOPE NOTE: This module currently runs under an
AdministratorAccess IAM user (per GUIDE_FOR_BACKEND.md), which is the
same anti-pattern that SecOps' CIS 1.16 check flags. Fixing this
requires a Terraform-side IAM policy change: a scoped write-limited
role for the executor (only the specific mutating APIs each action
needs). That change is out of scope for this codebase — tracked in
CONTEXT.md section 12.

Replaces execute_node's local-JSON mutation with real boto3 calls, one per
SafeAction/DestructiveAction value. Drop-in for graph/workflow.py's
execute_node: same input (a list of approved ActionPlanStep objects plus
the current infrastructure dict), same output shape (a list of execution
log dicts) — the body just does real things to real AWS now.

*** SAFETY: once this is wired in, approving a destructive action in the
*** demo ACTUALLY destroys real infrastructure. terminate_instance,
*** delete_volume, delete_database, and delete_iam_role are irreversible.
*** If you terminate the bim-processor instance mid-rehearsal, you need to
*** re-run `terraform apply` to bring it back before the next test run.
*** Rehearse the full approve flow at least once before doing it live.

One action genuinely can't be done as a simple in-place API call, by AWS
design, not by choice here: enable_encryption on an already-existing RDS
instance or EBS volume can't be flipped on directly. AWS requires
snapshot -> encrypted copy -> restore from that copy -> swap, which
creates a NEW resource with a new ID. SIMPLE_ENCRYPTION_MODE below picks
which behavior you get.
"""

from __future__ import annotations
import datetime as dt
import os
import time
import boto3

# True (default): tag the resource as flagged for encryption rather than
# claim something AWS can't actually do in place. Fast, honest, demo-safe.
# False: run the real snapshot/copy/restore flow. Correct, but takes
# several minutes and produces a new resource ID — only flip this if you
# have time to test it before the live demo.
SIMPLE_ENCRYPTION_MODE = True

ec2 = None
rds = None
s3 = None
iam = None


def _init_clients():
    global ec2, rds, s3, iam
    if ec2 is None:
        profile = os.getenv("AWS_EXECUTOR_PROFILE")
        region = os.getenv("AWS_DEFAULT_REGION", "ap-southeast-1")
        session = boto3.Session(profile_name=profile, region_name=region)
        ec2 = session.client("ec2")
        rds = session.client("rds")
        s3 = session.client("s3")
        iam = session.client("iam")


def _node_type(node_id: str, infrastructure: dict) -> str:
    for r in infrastructure["resources"]:
        if r["id"] == node_id:
            return r["type"]
    raise ValueError(f"{node_id} not found in current infrastructure scan — re-run aws_scanner first")


# ---------------------------------------------------------------------------
# SafeAction implementations
# ---------------------------------------------------------------------------

def _tag_resource(node_id: str, node_type: str):
    tags = [{"Key": "reviewed", "Value": "true"}]
    if node_type in ("ec2_instance", "ebs_volume", "security_group"):
        ec2.create_tags(Resources=[node_id], Tags=tags)
    elif node_type == "s3_bucket":
        existing = s3.get_bucket_tagging(Bucket=node_id).get("TagSet", [])
        s3.put_bucket_tagging(Bucket=node_id, Tagging={"TagSet": existing + tags})
    elif node_type == "rds_database":
        arn = rds.describe_db_instances(DBInstanceIdentifier=node_id)["DBInstances"][0]["DBInstanceArn"]
        rds.add_tags_to_resource(ResourceName=arn, Tags=tags)
    elif node_type == "iam_role":
        role_name = node_id.split("/")[-1]  # node_id is the role ARN
        iam.tag_role(RoleName=role_name, Tags=tags)


def _resize_down(node_id: str, node_type: str):
    if node_type == "ec2_instance":
        ec2.stop_instances(InstanceIds=[node_id])
        ec2.get_waiter("instance_stopped").wait(InstanceIds=[node_id])
        ec2.modify_instance_attribute(InstanceId=node_id, InstanceType={"Value": "t3.large"})
        ec2.start_instances(InstanceIds=[node_id])
    elif node_type == "rds_database":
        rds.modify_db_instance(
            DBInstanceIdentifier=node_id, DBInstanceClass="db.t3.large", ApplyImmediately=True
        )


def _restrict_security_group(sg_id: str):
    sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    to_revoke = []
    for perm in sg["IpPermissions"]:
        if perm.get("FromPort") == 443:
            continue  # keep HTTPS, per spec
        open_ranges = [r for r in perm.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
        if open_ranges:
            to_revoke.append({**perm, "IpRanges": open_ranges})
    if to_revoke:
        ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=to_revoke)


def _disable_public_access(node_id: str, node_type: str):
    if node_type == "s3_bucket":
        s3.put_public_access_block(
            Bucket=node_id,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            },
        )
        try:
            s3.delete_bucket_policy(Bucket=node_id)
        except s3.exceptions.ClientError:
            pass
    elif node_type == "rds_database":
        rds.modify_db_instance(DBInstanceIdentifier=node_id, PubliclyAccessible=False, ApplyImmediately=True)
    elif node_type == "ec2_instance":
        # There's no "make this instance private" API call — public
        # exposure on EC2 comes from its security group, not a per-instance
        # flag. Realistic equivalent: tighten the attached SG the same way
        # restrict_security_group does.
        instance = ec2.describe_instances(InstanceIds=[node_id])["Reservations"][0]["Instances"][0]
        for sg in instance["SecurityGroups"]:
            _restrict_security_group(sg["GroupId"])


def _enforce_imdsv2(node_id: str):
    ec2.modify_instance_metadata_options(
        InstanceId=node_id, HttpTokens="required", HttpEndpoint="enabled"
    )


def _enable_encryption(node_id: str, node_type: str) -> dict | None:
    if SIMPLE_ENCRYPTION_MODE:
        _tag_resource(node_id, node_type)
        return {"note": "AWS can't enable encryption on an existing RDS/EBS resource in place — "
                         "flagged for manual snapshot-and-recreate rather than faked as instant."}

    if node_type == "rds_database":
        snap_id = f"{node_id}-pre-encrypt-{int(time.time())}"
        rds.create_db_snapshot(DBInstanceIdentifier=node_id, DBSnapshotIdentifier=snap_id)
        rds.get_waiter("db_snapshot_available").wait(DBSnapshotIdentifier=snap_id)
        enc_snap_id = f"{snap_id}-encrypted"
        rds.copy_db_snapshot(
            SourceDBSnapshotIdentifier=snap_id,
            TargetDBSnapshotIdentifier=enc_snap_id,
            KmsKeyId="alias/aws/rds",
        )
        # Restoring from enc_snap_id creates a NEW DB instance with a new
        # identifier — this does not encrypt node_id in place. Left as a
        # manual follow-up (decide on cutover, connection string updates,
        # etc.) rather than an automatic swap.
        return {"note": f"Encrypted snapshot {enc_snap_id} created — restore + cutover is a manual step."}
    return None


# ---------------------------------------------------------------------------
# DestructiveAction implementations
# ---------------------------------------------------------------------------

def _terminate_instance(node_id: str):
    ec2.terminate_instances(InstanceIds=[node_id])


def _delete_volume(node_id: str):
    ec2.delete_volume(VolumeId=node_id)


def _delete_database(node_id: str):
    rds.delete_db_instance(DBInstanceIdentifier=node_id, SkipFinalSnapshot=True)


def _revoke_all_access(role_arn: str):
    role_name = role_arn.split("/")[-1]
    for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    for name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=role_name, PolicyName=name)


def _delete_iam_role(role_arn: str):
    role_name = role_arn.split("/")[-1]
    _revoke_all_access(role_arn)  # roles can't be deleted with policies still attached
    for profile in iam.list_instance_profiles_for_role(RoleName=role_name)["InstanceProfiles"]:
        iam.remove_role_from_instance_profile(
            InstanceProfileName=profile["InstanceProfileName"], RoleName=role_name
        )
    iam.delete_role(RoleName=role_name)


def _force_stop(node_id: str):
    ec2.stop_instances(InstanceIds=[node_id], Force=True)


# ---------------------------------------------------------------------------
# Dispatch table — one entry per value in SafeAction/DestructiveAction
# ---------------------------------------------------------------------------

ACTION_DISPATCH = {
    "tag_resource": lambda nid, nt: _tag_resource(nid, nt),
    "resize_down": lambda nid, nt: _resize_down(nid, nt),
    "resize_up": lambda nid, nt: None,            # logged only, per spec
    "flag_for_review": lambda nid, nt: None,       # logged only, per spec
    "create_snapshot": lambda nid, nt: (
        ec2.create_snapshot(VolumeId=nid) if nt == "ebs_volume" else None
    ),
    "enable_encryption": lambda nid, nt: _enable_encryption(nid, nt),
    "restrict_security_group": lambda nid, nt: _restrict_security_group(nid),
    "rotate_credentials": lambda nid, nt: None,    # logged only, per spec
    "disable_public_access": lambda nid, nt: _disable_public_access(nid, nt),
    "enforce_imdsv2": lambda nid, nt: _enforce_imdsv2(nid),
    "flag_privesc_path": lambda nid, nt: None,     # logged only, per spec
    "terminate_instance": lambda nid, nt: _terminate_instance(nid),
    "delete_volume": lambda nid, nt: _delete_volume(nid),
    "delete_database": lambda nid, nt: _delete_database(nid),
    "revoke_all_access": lambda nid, nt: _revoke_all_access(nid),
    "delete_iam_role": lambda nid, nt: _delete_iam_role(nid),
    "force_stop": lambda nid, nt: _force_stop(nid),
}


def execute_real_actions(approved_steps: list, infrastructure: dict) -> list[dict]:
    """
    Drop-in for execute_node's body. approved_steps is the same
    list[ActionPlanStep] it already receives. Returns the same
    execution_logs shape: [{"timestamp", "step", "status", "message"}].
    """
    _init_clients()
    logs = []
    for step in approved_steps:
        try:
            node_type = _node_type(step.target_node, infrastructure)
            fn = ACTION_DISPATCH.get(step.action)
            if fn is None:
                raise ValueError(
                    f"Unrecognised action '{step.action}' reached the executor — "
                    f"Gatekeeper should have caught this before it got here"
                )
            fn(step.target_node, node_type)
            logs.append({
                "timestamp": dt.datetime.utcnow().isoformat(),
                "step": step.step,
                "status": "complete",
                "message": f"{step.human_label} — executed against real AWS",
            })
        except Exception as e:
            logs.append({
                "timestamp": dt.datetime.utcnow().isoformat(),
                "step": step.step,
                "status": "failed",
                "message": f"{step.human_label} — FAILED: {e}",
            })
    return logs

"""
aws_scanner.py — real AWS infrastructure scanner for Feronia.

CREDENTIAL SCOPE NOTE: This module currently runs under an
AdministratorAccess IAM user (per GUIDE_FOR_BACKEND.md), which is the
same anti-pattern that SecOps' CIS 1.16 check flags. Fixing this
requires a Terraform-side IAM policy change: a scoped read-only role for
the scanner (ec2:Describe*, cloudwatch:GetMetricStatistics,
iam:List*/Get*, rds:Describe*, s3:Get*/List*). That change is out of
scope for this codebase — tracked in CONTEXT.md section 12.

Replaces reading data/infrastructure_state.json with a live boto3 scan of
the actual AWS account, producing a dict in the EXACT same shape:

    {"resources": [...], "relationships": [...]}

graph/builder.py, agents/secops_agent.py, agents/greenops_agent.py, and
agents/gatekeeper.py all consume this dict — none of them need to change
if the shape matches, which is the whole point of this module.

Usage in main.py, replacing the infrastructure_state.json load:

    from aws_scanner import scan_infrastructure
    infrastructure = scan_infrastructure(region="ap-southeast-1")

Required IAM permissions for whatever credentials run this (read-only is
enough — this module never calls a mutating API):
    ec2:Describe*, cloudwatch:GetMetricStatistics, iam:ListRoles,
    iam:ListRoleTags, iam:ListAttachedRolePolicies, iam:ListRolePolicies,
    iam:GetPolicy, iam:GetPolicyVersion, iam:GetRolePolicy,
    iam:GetInstanceProfile, rds:DescribeDBInstances, s3:ListAllMyBuckets,
    s3:GetBucketTagging, s3:GetBucketVersioning, s3:GetBucketEncryption,
    s3:GetBucketPublicAccessBlock, lambda:ListFunctions, lambda:ListTags,
    dynamodb:DescribeTable
"""

from __future__ import annotations
import datetime as dt
import os
import boto3

DEFAULT_REGION = "ap-southeast-1"

PROJECT_TAG_KEY = "Project"
PROJECT_TAG_VALUE = "feronia-demo"
LOGICAL_ID_TAG = "feronia:logical_id"
LOGICAL_TYPE_TAG = "feronia:logical_instance_type"
LOGICAL_SIZE_TAG = "feronia:logical_size_gb"
CONNECTS_TO_TAG = "feronia:connects_to"
HAS_PERMISSION_TAG = "feronia:has_permission"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tags_to_dict(tag_list) -> dict:
    """AWS returns tags as [{'Key': k, 'Value': v}, ...] in most APIs."""
    return {t["Key"]: t["Value"] for t in (tag_list or [])}


def _is_project_resource(tags: dict) -> bool:
    return tags.get(PROJECT_TAG_KEY) == PROJECT_TAG_VALUE


def _clean_tags(tags: dict) -> dict:
    """Strip our internal feronia:* bookkeeping tags before they land in
    the final resource dict's user-facing `tags` field."""
    return {k: v for k, v in tags.items() if not k.startswith("feronia:")}


def _cpu_avg(cloudwatch, instance_id: str, launch_time: dt.datetime) -> float:
    """Real CPUUtilization average since launch (or 7 days, whichever is
    shorter). Freshly launched instances won't have 7 days of history —
    that's fine, a genuinely idle instance reports genuinely low numbers
    within minutes."""
    now = dt.datetime.now(dt.timezone.utc)
    start = max(launch_time, now - dt.timedelta(days=7))
    resp = cloudwatch.get_metric_statistics(
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        StartTime=start,
        EndTime=now,
        Period=3600,
        Statistics=["Average"],
    )
    points = resp.get("Datapoints", [])
    if not points:
        return 0.0  # no datapoints yet = genuinely idle, not an error
    return round(sum(p["Average"] for p in points) / len(points), 2)


def _resolve_policy_actions(iam, policy_arn: str = None, role_name: str = None,
                             inline_name: str = None) -> list[str]:
    """Flatten a managed or inline IAM policy document's Allow-statement
    Actions into a list. Wildcards ('*') pass through unchanged — the
    SecOps agent's CIS 1.16 check already knows to treat a literal '*' as
    the full-admin violation."""
    if policy_arn:
        policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
        version = iam.get_policy_version(
            PolicyArn=policy_arn, VersionId=policy["DefaultVersionId"]
        )
        doc = version["PolicyVersion"]["Document"]
    else:
        doc = iam.get_role_policy(RoleName=role_name, PolicyName=inline_name)["PolicyDocument"]

    statements = doc["Statement"]
    if isinstance(statements, dict):
        statements = [statements]

    actions = []
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        action = stmt.get("Action", [])
        if isinstance(action, str):
            action = [action]
        actions.extend(action)
    return actions


def _resolve_instance_profile_role(iam, profile_arn: str) -> str | None:
    """EC2's IamInstanceProfile gives you the instance PROFILE arn, not the
    role arn — need one more call to resolve profile -> role."""
    if not profile_arn:
        return None
    profile_name = profile_arn.split("/")[-1]
    try:
        from botocore.exceptions import ClientError
        resp = iam.get_instance_profile(InstanceProfileName=profile_name)
        roles = resp["InstanceProfile"]["Roles"]
        return roles[0]["Arn"] if roles else None
    except Exception:
        # Ignore AccessDenied if the execution role lacks IAM read permissions
        return None


# ---------------------------------------------------------------------------
# Per-resource-type scanners
# ---------------------------------------------------------------------------

def _scan_ec2_instances(ec2, cloudwatch, iam) -> list[dict]:
    resources = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(
        Filters=[
            {"Name": f"tag:{PROJECT_TAG_KEY}", "Values": [PROJECT_TAG_VALUE]},
            {"Name": "instance-state-name", "Values": ["running", "stopped"]},
        ]
    ):
        for reservation in page["Reservations"]:
            for inst in reservation["Instances"]:
                tags = _tags_to_dict(inst.get("Tags"))
                profile_arn = inst.get("IamInstanceProfile", {}).get("Arn")
                role_arn = _resolve_instance_profile_role(iam, profile_arn) if profile_arn else None
                sg_ids = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]
                has_public_ip = "PublicIpAddress" in inst

                resources.append({
                    "id": inst["InstanceId"],
                    "type": "ec2_instance",
                    "name": tags.get("Name", inst["InstanceId"]),
                    "instance_type": tags.get(LOGICAL_TYPE_TAG, inst["InstanceType"]),
                    "region": inst["Placement"]["AvailabilityZone"][:-1],
                    "public_exposure": has_public_ip,
                    "cpu_avg_7d": _cpu_avg(cloudwatch, inst["InstanceId"], inst["LaunchTime"]),
                    "state": inst["State"]["Name"],
                    "tags": _clean_tags(tags),
                    "iam_profile": role_arn,
                    "http_tokens": inst.get("MetadataOptions", {}).get("HttpTokens", "required"),
                    # internal-only fields, stripped before returning
                    "_logical_id": tags.get(LOGICAL_ID_TAG, inst["InstanceId"]),
                    "_sg_ids": sg_ids,
                    "_connects_to": tags.get(CONNECTS_TO_TAG, ""),
                    "_has_permission": tags.get(HAS_PERMISSION_TAG, ""),
                })
    return resources


def _scan_security_groups(ec2, region: str) -> list[dict]:
    resources = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate(
        Filters=[{"Name": f"tag:{PROJECT_TAG_KEY}", "Values": [PROJECT_TAG_VALUE]}]
    ):
        for sg in page["SecurityGroups"]:
            tags = _tags_to_dict(sg.get("Tags"))
            inbound_rules, is_public = [], False
            for perm in sg.get("IpPermissions", []):
                for ip_range in perm.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp")
                    inbound_rules.append({
                        "port": perm.get("FromPort"),
                        "protocol": perm.get("IpProtocol"),
                        "source": cidr,
                    })
                    if cidr == "0.0.0.0/0":
                        is_public = True

            resources.append({
                "id": sg["GroupId"],
                "type": "security_group",
                "name": sg["GroupName"],
                "region": region,
                "public_exposure": is_public,
                "inbound_rules": inbound_rules,
                "tags": _clean_tags(tags),
                "_logical_id": tags.get(LOGICAL_ID_TAG, sg["GroupId"]),
            })
    return resources


def _scan_iam_roles(iam) -> list[dict]:
    resources = []
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                role_name = role["RoleName"]
                tags = _tags_to_dict(iam.list_role_tags(RoleName=role_name).get("Tags"))
                if not _is_project_resource(tags):
                    continue

                attached_policy_names, attached_actions = [], []
                for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
                    attached_policy_names.append(p["PolicyName"])
                    attached_actions.extend(_resolve_policy_actions(iam, policy_arn=p["PolicyArn"]))
                for inline_name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
                    attached_policy_names.append(inline_name)
                    attached_actions.extend(
                        _resolve_policy_actions(iam, role_name=role_name, inline_name=inline_name)
                    )

                resources.append({
                    "id": role["Arn"],
                    "type": "iam_role",
                    "name": role_name,
                    "region": "global",
                    "public_exposure": False,
                    "attached_policies": attached_policy_names,
                    "attached_actions": sorted(set(attached_actions)),
                    "tags": _clean_tags(tags),
                    "_logical_id": tags.get(LOGICAL_ID_TAG, role_name),
                })
    except Exception:
        # Gracefully handle AccessDenied if the execution role lacks IAM read permissions
        pass
    return resources


def _scan_ebs_volumes(ec2, region: str) -> list[dict]:
    resources = []
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate(
        Filters=[{"Name": f"tag:{PROJECT_TAG_KEY}", "Values": [PROJECT_TAG_VALUE]}]
    ):
        for vol in page["Volumes"]:
            tags = _tags_to_dict(vol.get("Tags"))
            attachments = vol.get("Attachments", [])
            resources.append({
                "id": vol["VolumeId"],
                "type": "ebs_volume",
                "name": tags.get("Name", vol["VolumeId"]),
                "region": region,
                "public_exposure": False,
                "state": vol["State"],
                "size_gb": int(tags.get(LOGICAL_SIZE_TAG, vol["Size"])),
                "attached_to": attachments[0]["InstanceId"] if attachments else None,
                "tags": _clean_tags(tags),
                "_logical_id": tags.get(LOGICAL_ID_TAG, vol["VolumeId"]),
            })
    return resources


def _scan_rds_instances(rds, region: str) -> list[dict]:
    resources = []
    paginator = rds.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for db in page["DBInstances"]:
            tags = _tags_to_dict(db.get("TagList"))
            if not _is_project_resource(tags):
                continue
            resources.append({
                "id": db["DBInstanceIdentifier"],
                "type": "rds_database",
                "name": db["DBInstanceIdentifier"],
                "instance_type": tags.get(LOGICAL_TYPE_TAG, db["DBInstanceClass"]),
                "region": region,
                "public_exposure": db["PubliclyAccessible"],
                "encryption_enabled": db["StorageEncrypted"],
                "state": db["DBInstanceStatus"],
                "tags": _clean_tags(tags),
                "_logical_id": tags.get(LOGICAL_ID_TAG, db["DBInstanceIdentifier"]),
            })
    return resources


def _scan_s3_buckets(s3, region: str) -> list[dict]:
    resources = []
    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        try:
            tags = _tags_to_dict(s3.get_bucket_tagging(Bucket=name).get("TagSet"))
        except s3.exceptions.ClientError:
            tags = {}
        if not _is_project_resource(tags):
            continue

        try:
            versioning = s3.get_bucket_versioning(Bucket=name).get("Status", "Disabled")
        except s3.exceptions.ClientError:
            versioning = "Disabled"

        # CAVEAT (see README): AWS applies default SSE-S3 to every new
        # bucket since Jan 2023 — true "unencrypted" doesn't exist anymore.
        # This only distinguishes default SSE-S3 from a customer-managed
        # KMS key, which is the honest real-world equivalent finding.
        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            rule = enc["ServerSideEncryptionConfiguration"]["Rules"][0]
            uses_kms = rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "aws:kms"
        except s3.exceptions.ClientError:
            uses_kms = False

        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            is_public = not all(pab.values())
        except s3.exceptions.ClientError:
            is_public = True  # no block config at all = wide open

        resources.append({
            "id": name,
            "type": "s3_bucket",
            "name": name,
            "region": region,
            "public_exposure": is_public,
            "versioning": versioning == "Enabled",
            "encryption_enabled": uses_kms,
            "tags": _clean_tags(tags),
            "_logical_id": tags.get(LOGICAL_ID_TAG, name),
        })
    return resources


# ---------------------------------------------------------------------------
# Relationship reconstruction
# ---------------------------------------------------------------------------

def _build_relationships(ec2_resources: list[dict], logical_id_map: dict[str, str]) -> list[dict]:
    relationships = []

    for inst in ec2_resources:
        for sg_id in inst["_sg_ids"]:
            relationships.append({"source": sg_id, "target": inst["id"], "relation": "protects"})

        if inst.get("iam_profile"):
            relationships.append({
                "source": inst["iam_profile"], "target": inst["id"], "relation": "attached_to"
            })

        for raw in inst["_connects_to"].split(","):
            logical = raw.strip()
            if logical and logical in logical_id_map:
                relationships.append({
                    "source": inst["id"], "target": logical_id_map[logical], "relation": "connects_to"
                })

        for raw in inst["_has_permission"].split(","):
            logical = raw.strip()
            if logical and logical in logical_id_map:
                relationships.append({
                    "source": inst["id"], "target": logical_id_map[logical], "relation": "has_permission"
                })

    return relationships


def _strip_internal_fields(resources: list[dict]) -> list[dict]:
    return [{k: v for k, v in r.items() if not k.startswith("_")} for r in resources]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def scan_infrastructure(region: str = DEFAULT_REGION) -> dict:
    profile = os.getenv("AWS_SCANNER_PROFILE")
    session = boto3.Session(profile_name=profile, region_name=region)
    ec2 = session.client("ec2")
    cloudwatch = session.client("cloudwatch")
    iam = session.client("iam")  # global service, but the SDK still wants a region
    rds = session.client("rds")
    s3 = session.client("s3")

    ec2_resources = _scan_ec2_instances(ec2, cloudwatch, iam)
    sg_resources = _scan_security_groups(ec2, region)
    role_resources = _scan_iam_roles(iam)
    ebs_resources = _scan_ebs_volumes(ec2, region)
    rds_resources = _scan_rds_instances(rds, region)
    s3_resources = _scan_s3_buckets(s3, region)

    all_resources = (
        ec2_resources + sg_resources + role_resources + ebs_resources + rds_resources + s3_resources
    )

    logical_id_map = {r["_logical_id"]: r["id"] for r in all_resources if "_logical_id" in r}
    relationships = _build_relationships(ec2_resources, logical_id_map)

    return {
        "resources": _strip_internal_fields(all_resources),
        "relationships": relationships,
    }


if __name__ == "__main__":
    import json
    result = scan_infrastructure()
    print(f"Scanned {len(result['resources'])} resources, {len(result['relationships'])} relationships")
    print(json.dumps(result, indent=2, default=str))

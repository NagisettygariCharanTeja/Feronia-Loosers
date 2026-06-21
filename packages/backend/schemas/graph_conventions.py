NODE_TYPE = "type"
NODE_NAME = "name"
NODE_REGION = "region"
NODE_INSTANCE_TYPE = "instance_type"
NODE_PUBLIC_EXPOSURE = "public_exposure"
NODE_TAGS = "tags"
NODE_STATE = "state"
NODE_CPU_AVG_7D = "cpu_avg_7d"
NODE_IMDS_HTTP_TOKENS = "http_tokens"
NODE_ATTACHED_ACTIONS = "attached_actions"

EDGE_RELATION = "relation"
EDGE_PORT = "port"
EDGE_PROTOCOL = "protocol"

EC2_INSTANCE = "ec2_instance"
S3_BUCKET = "s3_bucket"
RDS_DATABASE = "rds_database"
SECURITY_GROUP = "security_group"
IAM_ROLE = "iam_role"
LOAD_BALANCER = "load_balancer"
EBS_VOLUME = "ebs_volume"

# Actions valid only for specific node types. Actions not listed here
# (tag_resource, flag_for_review, flag_privesc_path, rotate_credentials,
# create_snapshot) are intentionally omitted — no restriction needed.
ACTION_VALID_NODE_TYPES = {
    "terminate_instance": {EC2_INSTANCE},
    "force_stop": {EC2_INSTANCE},
    "resize_down": {EC2_INSTANCE, RDS_DATABASE},
    "resize_up": {EC2_INSTANCE, RDS_DATABASE},
    "enforce_imdsv2": {EC2_INSTANCE},
    "delete_volume": {EBS_VOLUME},
    "delete_database": {RDS_DATABASE},
    "delete_iam_role": {IAM_ROLE},
    "revoke_all_access": {IAM_ROLE},
    "restrict_security_group": {SECURITY_GROUP},
    "disable_public_access": {S3_BUCKET, RDS_DATABASE, EC2_INSTANCE},
    "enable_encryption": {RDS_DATABASE, EBS_VOLUME, S3_BUCKET},
}

CONNECTS_TO = "connects_to"
HAS_PERMISSION = "has_permission"
ROUTES_TRAFFIC_TO = "routes_traffic_to"
ATTACHED_TO = "attached_to"
PROTECTS = "protects"

"""Static verification test: boto3 API calls map to IAM permissions in Terraform."""

import ast
import re
from pathlib import Path


def _extract_iam_actions_from_terraform() -> set[str]:
    """Parse IAM actions defined in terraform/modules/guard/iam.tf and main.tf."""
    tf_dir = Path("terraform/modules/guard")
    iam_tf = (tf_dir / "iam.tf").read_text(encoding="utf-8")
    main_tf = (tf_dir / "main.tf").read_text(encoding="utf-8")

    all_actions: set[str] = set()

    # Match all quoted strings resembling IAM actions like "ec2:DescribeInstances"
    iam_action_pattern = re.compile(r'"([a-z0-9-]+:[A-Za-z0-9*]+)"')
    for text in [iam_tf, main_tf]:
        for match in iam_action_pattern.findall(text):
            all_actions.add(match)

    return all_actions


def _extract_boto3_methods_from_python() -> set[str]:
    """Scan src/bill_shock_guard for boto3 method calls on AWS clients."""
    src_dir = Path("src/bill_shock_guard")
    method_names: set[str] = set()

    known_aws_methods = {
        "describe_instances",
        "describe_addresses",
        "describe_nat_gateways",
        "describe_volumes",
        "describe_snapshots",
        "describe_regions",
        "describe_load_balancers",
        "describe_target_groups",
        "describe_target_health",
        "describe_tags",
        "describe_db_instances",
        "list_notebook_instances",
        "describe_notebook_instance",
        "list_tags",
        "get_metric_data",
        "get_metric_statistics",
        "get_caller_identity",
        "stop_instances",
        "release_address",
        "delete_nat_gateway",
        "create_snapshot",
        "delete_volume",
        "delete_load_balancer",
        "stop_db_instance",
        "stop_notebook_instance",
        "publish",
        "list_subscriptions_by_topic",
        "get_item",
        "put_item",
        "update_item",
        "scan",
        "query",
        "get_parameter",
    }

    for py_file in src_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute):
                    if func.attr in known_aws_methods:
                        method_names.add(func.attr)
                # Check for paginate(client, "method_name", ...)
                elif isinstance(func, ast.Name) and func.id == "paginate":
                    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                        arg_val = node.args[1].value
                        if isinstance(arg_val, str) and arg_val in known_aws_methods:
                            method_names.add(arg_val)

    return method_names


# Mapping from boto3 method names to required IAM actions
BOTO3_TO_IAM_MAP: dict[str, list[str]] = {
    "describe_instances": ["ec2:DescribeInstances"],
    "describe_addresses": ["ec2:DescribeAddresses"],
    "describe_nat_gateways": ["ec2:DescribeNatGateways"],
    "describe_volumes": ["ec2:DescribeVolumes"],
    "describe_snapshots": ["ec2:DescribeSnapshots"],
    "describe_regions": ["ec2:DescribeRegions"],
    "describe_load_balancers": ["elasticloadbalancing:DescribeLoadBalancers"],
    "describe_target_groups": ["elasticloadbalancing:DescribeTargetGroups"],
    "describe_target_health": ["elasticloadbalancing:DescribeTargetHealth"],
    "describe_tags": ["elasticloadbalancing:DescribeTags"],
    "describe_db_instances": ["rds:DescribeDBInstances"],
    "list_notebook_instances": ["sagemaker:ListNotebookInstances"],
    "describe_notebook_instance": ["sagemaker:DescribeNotebookInstance"],
    "list_tags": ["sagemaker:ListTags"],
    "get_metric_data": ["cloudwatch:GetMetricData"],
    "get_metric_statistics": ["cloudwatch:GetMetricStatistics"],
    "get_caller_identity": ["sts:GetCallerIdentity"],
    "stop_instances": ["ec2:StopInstances"],
    "release_address": ["ec2:ReleaseAddress"],
    "delete_nat_gateway": ["ec2:DeleteNatGateway"],
    "create_snapshot": ["ec2:CreateSnapshot", "ec2:CreateTags"],
    "delete_volume": ["ec2:DeleteVolume"],
    "delete_load_balancer": ["elasticloadbalancing:DeleteLoadBalancer"],
    "stop_db_instance": ["rds:StopDBInstance"],
    "stop_notebook_instance": ["sagemaker:StopNotebookInstance"],
    "publish": ["sns:Publish"],
    "list_subscriptions_by_topic": ["sns:ListSubscriptionsByTopic"],
    "get_item": ["dynamodb:GetItem"],
    "put_item": ["dynamodb:PutItem"],
    "update_item": ["dynamodb:UpdateItem"],
    "scan": ["dynamodb:Scan"],
    "query": ["dynamodb:Query"],
    "get_parameter": ["ssm:GetParameter"],
}


def test_iam_actions_cover_all_boto3_methods() -> None:
    """Invariant I5 & Drift Prevention: boto3 methods in code must exist in Terraform IAM."""
    tf_iam_actions = _extract_iam_actions_from_terraform()
    code_boto3_methods = _extract_boto3_methods_from_python()

    missing_mappings: list[str] = []
    uncovered_methods: list[str] = []

    for method in sorted(code_boto3_methods):
        if method not in BOTO3_TO_IAM_MAP:
            missing_mappings.append(method)
            continue

        required_actions = BOTO3_TO_IAM_MAP[method]
        for req_act in required_actions:
            if req_act not in tf_iam_actions:
                uncovered_methods.append(
                    f"Method '{method}' requires '{req_act}' which is missing in Terraform"
                )

    assert not missing_mappings, f"Boto3 methods missing IAM mappings: {missing_mappings}"
    assert not uncovered_methods, (
        f"Boto3 methods used in code lack IAM permissions in Terraform: {uncovered_methods}"
    )


def test_iam_action_mappings_are_valid_format() -> None:
    """Assert all Terraform IAM actions follow standard service:Action naming."""
    tf_iam_actions = _extract_iam_actions_from_terraform()
    assert len(tf_iam_actions) > 15
    for action in tf_iam_actions:
        assert ":" in action
        service, act = action.split(":", 1)
        assert service in {
            "ec2",
            "elasticloadbalancing",
            "rds",
            "sagemaker",
            "cloudwatch",
            "sts",
            "dynamodb",
            "sns",
            "logs",
            "ssm",
        }
        assert len(act) > 0

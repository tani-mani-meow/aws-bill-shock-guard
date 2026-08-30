data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    sid     = "LambdaAssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "guard_permissions" {
  # 1. Read statement (always required for discovery, metrics, and safety checks)
  statement {
    sid    = "ReadServiceResources"
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeAddresses",
      "ec2:DescribeNatGateways",
      "ec2:DescribeVolumes",
      "ec2:DescribeSnapshots",
      "ec2:DescribeRegions",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticloadbalancing:DescribeTags",
      "rds:DescribeDBInstances",
      "sagemaker:ListNotebookInstances",
      "sagemaker:DescribeNotebookInstance",
      "sagemaker:ListTags",
      "cloudwatch:GetMetricData",
      "cloudwatch:GetMetricStatistics",
      "sts:GetCallerIdentity"
    ]
    resources = ["*"]
  }

  # 2. DynamoDB state table operations (scoped to table ARN only)
  statement {
    sid    = "DynamoDBStateTableAccess"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:Query",
      "dynamodb:Scan"
    ]
    resources = [aws_dynamodb_table.state.arn]
  }

  # 3. SNS delivery operations (scoped to topic ARN only)
  statement {
    sid    = "SNSPublishAlerts"
    effect = "Allow"
    actions = [
      "sns:Publish",
      "sns:ListSubscriptionsByTopic"
    ]
    resources = [aws_sns_topic.alerts.arn]
  }

  # 4. CloudWatch Logs (scoped to lambda log group)
  statement {
    sid    = "CloudWatchLogsWrite"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["${aws_cloudwatch_log_group.lambda_logs.arn}:*"]
  }

  # 5. SSM GetParameter for Telegram bot token (granted ONLY when Telegram is enabled)
  dynamic "statement" {
    for_each = var.telegram_enabled && var.telegram_token_ssm_param != "" ? [1] : []
    content {
      sid    = "SSMTelegramTokenAccess"
      effect = "Allow"
      actions = [
        "ssm:GetParameter"
      ]
      resources = [
        "arn:aws:ssm:*:*:parameter/${trimprefix(var.telegram_token_ssm_param, "/")}"
      ]
    }
  }

  # 6. Mutating statements generated strictly from enabled_actions (Invariant I5 defense in depth)
  dynamic "statement" {
    for_each = length(local.active_mutating_actions) > 0 ? [1] : []
    content {
      sid       = "MutatingActions"
      effect    = "Allow"
      actions   = local.active_mutating_actions
      resources = ["*"]
    }
  }

  # 7. Deny mutating actions on protected resources tagged with protect_tag_key (Invariants I3 and I10)
  dynamic "statement" {
    for_each = length(local.tag_protectable_mutating_actions) > 0 ? [1] : []
    content {
      sid       = "DenyMutatingProtectedResources"
      effect    = "Deny"
      actions   = local.tag_protectable_mutating_actions
      resources = ["*"]

      condition {
        test     = "Null"
        variable = "aws:ResourceTag/${var.protect_tag_key}"
        values   = ["false"] # Null=false means the tag exists on the target resource
      }
    }
  }
}

resource "aws_iam_role" "lambda_exec" {
  name               = "${var.name_prefix}-lambda-exec-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = local.common_tags
}

resource "aws_iam_policy" "guard_policy" {
  name        = "${var.name_prefix}-guard-policy"
  description = "Least privilege IAM policy for Bill Shock Guard scanner Lambda"
  policy      = data.aws_iam_policy_document.guard_permissions.json
  tags        = local.common_tags
}

resource "aws_iam_role_policy_attachment" "guard_policy_attach" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.guard_policy.arn
}

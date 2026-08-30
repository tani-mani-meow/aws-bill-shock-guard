locals {
  # Merge explicit threshold inputs with canonical defaults
  thresholds = {
    ec2_idle_window_hours              = lookup(var.thresholds, "ec2_idle_window_hours", 24)
    ec2_idle_cpu_avg_pct               = lookup(var.thresholds, "ec2_idle_cpu_avg_pct", 5.0)
    ec2_idle_network_avg_bytes_per_sec = lookup(var.thresholds, "ec2_idle_network_avg_bytes_per_sec", 10000)
    nat_idle_window_hours              = lookup(var.thresholds, "nat_idle_window_hours", 24)
    ebs_unattached_days                = lookup(var.thresholds, "ebs_unattached_days", 7)
    elb_idle_window_hours              = lookup(var.thresholds, "elb_idle_window_hours", 168)
    rds_idle_window_hours              = lookup(var.thresholds, "rds_idle_window_hours", 168)
  }

  # Build the canonical JSON configuration document matching Section 7
  bsg_config = {
    dry_run             = var.dry_run
    grace_hours         = var.grace_hours
    regions             = var.regions
    protect_tag_key     = var.protect_tag_key
    managed_tag_keys    = var.managed_tag_keys
    ignore_resource_ids = var.ignore_resource_ids
    enabled_actions     = var.enabled_actions
    max_actions_per_run = var.max_actions_per_run
    display_tz          = var.display_tz
    thresholds          = local.thresholds
    notify = {
      sns_topic_arn = aws_sns_topic.alerts.arn
      telegram = {
        enabled         = var.telegram_enabled
        chat_id         = var.telegram_chat_id
        token_ssm_param = var.telegram_token_ssm_param
      }
    }
    state_table = aws_dynamodb_table.state.name
  }

  bsg_config_json = jsonencode(local.bsg_config)

  common_tags = merge(
    {
      "ManagedBy"   = "Terraform"
      "Application" = "BillShockGuard"
    },
    var.tags
  )

  # ActionKind -> Mutating IAM permissions mapping (Section 9.2)
  action_to_iam = {
    ec2_stop                  = ["ec2:StopInstances"]
    eip_release               = ["ec2:ReleaseAddress"]
    nat_delete                = ["ec2:DeleteNatGateway"]
    ebs_delete_after_snapshot = ["ec2:CreateSnapshot", "ec2:DescribeSnapshots", "ec2:CreateTags", "ec2:DeleteVolume"]
    elb_delete                = ["elasticloadbalancing:DeleteLoadBalancer"]
    rds_stop                  = ["rds:StopDBInstance"]
    sm_notebook_stop          = ["sagemaker:StopNotebookInstance"]
  }

  # Active mutating IAM actions based strictly on var.enabled_actions (Invariant I5 defense in depth)
  active_mutating_actions = distinct(flatten([
    for a in var.enabled_actions : lookup(local.action_to_iam, a, [])
  ]))

  # Actions that delete/mutate resources and support aws:ResourceTag condition
  tag_protectable_actions_map = {
    ec2_stop                  = ["ec2:StopInstances"]
    eip_release               = ["ec2:ReleaseAddress"]
    nat_delete                = ["ec2:DeleteNatGateway"]
    ebs_delete_after_snapshot = ["ec2:DeleteVolume"]
    elb_delete                = ["elasticloadbalancing:DeleteLoadBalancer"]
    rds_stop                  = ["rds:StopDBInstance"]
    sm_notebook_stop          = ["sagemaker:StopNotebookInstance"]
  }

  tag_protectable_mutating_actions = distinct(flatten([
    for a in var.enabled_actions : lookup(local.tag_protectable_actions_map, a, [])
  ]))
}

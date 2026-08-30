variable "dry_run" {
  type        = bool
  default     = true
  description = "If true, findings are recorded and notifications sent, but mutating AWS actions are skipped (Invariant I1)."
}

variable "grace_hours" {
  type        = number
  default     = 24
  description = "Hours between warning delivery and executing mutating action (Invariant I2). Must be >= 1."

  validation {
    condition     = var.grace_hours >= 1
    error_message = "grace_hours must be at least 1 hour."
  }
}

variable "regions" {
  type        = list(string)
  default     = ["*"]
  description = "AWS regions to scan. Use ['*'] to dynamically scan all enabled regions in the account."
}

variable "protect_tag_key" {
  type        = string
  default     = "bsg:keep"
  description = "Resource tag key that exempts a resource from any mutating action (Invariants I3 and I10)."
}

variable "managed_tag_keys" {
  type = list(string)
  default = [
    "aws:autoscaling:groupName",
    "eks:cluster-name",
    "aws:eks:cluster-name",
    "elasticbeanstalk:environment-name"
  ]
  description = "Tag keys indicating a resource is managed by another service and must never be touched."
}

variable "ignore_resource_ids" {
  type        = list(string)
  default     = []
  description = "Explicit list of resource IDs (e.g. ['i-0123456789abcdef0']) never to warn or act upon."
}

variable "enabled_actions" {
  type        = list(string)
  default     = ["ec2_stop", "eip_release"]
  description = "Mutating actions permitted. Supported: ec2_stop, eip_release, nat_delete, ebs_delete_after_snapshot, elb_delete, rds_stop, sm_notebook_stop."

  validation {
    condition = alltrue([
      for a in var.enabled_actions : contains([
        "ec2_stop",
        "eip_release",
        "nat_delete",
        "ebs_delete_after_snapshot",
        "elb_delete",
        "rds_stop",
        "sm_notebook_stop"
      ], a)
    ])
    error_message = "enabled_actions contains an invalid ActionKind."
  }
}

variable "max_actions_per_run" {
  type        = number
  default     = 5
  description = "Circuit breaker: maximum mutating actions to execute per scan run (Invariant I7). Must be >= 0."

  validation {
    condition     = var.max_actions_per_run >= 0
    error_message = "max_actions_per_run must be non-negative."
  }
}

variable "display_tz" {
  type        = string
  default     = "Asia/Kolkata"
  description = "Timezone string used for formatting timestamps in notification digests."
}

variable "thresholds" {
  type = object({
    ec2_idle_window_hours              = optional(number, 24)
    ec2_idle_cpu_avg_pct               = optional(number, 5.0)
    ec2_idle_network_avg_bytes_per_sec = optional(number, 10000)
    nat_idle_window_hours              = optional(number, 24)
    ebs_unattached_days                = optional(number, 7)
    elb_idle_window_hours              = optional(number, 168)
    rds_idle_window_hours              = optional(number, 168)
  })
  default     = {}
  description = "Detection thresholds for idle resource rules."
}

variable "notification_emails" {
  type        = list(string)
  default     = []
  description = "Email addresses to subscribe to the SNS alerts topic. Subscribers must confirm via email link."
}

variable "telegram_enabled" {
  type        = bool
  default     = false
  description = "Enable Telegram alert notifications in addition to SNS."
}

variable "telegram_chat_id" {
  type        = string
  default     = ""
  description = "Telegram destination chat ID for alert digests."
}

variable "telegram_token_ssm_param" {
  type        = string
  default     = ""
  description = "SSM Parameter Store parameter name storing the Telegram bot token (SecureString). Token is never in Terraform state."
}

variable "schedule_expression" {
  type        = string
  default     = "rate(6 hours)"
  description = "EventBridge cron/rate expression for scheduling the scan Lambda."
}

variable "enabled" {
  type        = bool
  default     = true
  description = "Master kill switch: enables or disables the EventBridge schedule rule."
}

variable "name_prefix" {
  type        = string
  default     = "bsg"
  description = "Resource name prefix for all AWS resources created by the module."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to all taggable resources created by this module."
}

variable "lambda_source_dir" {
  type        = string
  default     = ""
  description = "Directory containing bill_shock_guard source to package for Lambda. If empty, defaults to repo build/lambda."
}

variable "lambda_zip_path" {
  type        = string
  default     = ""
  description = "Optional pre-packaged zip file for Lambda. If provided, skips local archive_file zipping."
}

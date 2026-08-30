variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region for deployment and scanning."
}

variable "dry_run" {
  type        = bool
  default     = true
  description = "Whether to run in dry-run mode (no mutating actions performed)."
}

variable "notification_emails" {
  type        = list(string)
  default     = []
  description = "Email addresses for SNS alert digest notifications."
}

variable "enabled_actions" {
  type        = list(string)
  default     = ["ec2_stop", "eip_release"]
  description = "Allowed mutating actions once dry_run is disabled."
}

variable "name_prefix" {
  type        = string
  default     = "bsg"
  description = "Resource name prefix."
}

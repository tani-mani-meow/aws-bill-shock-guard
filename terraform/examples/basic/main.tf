provider "aws" {
  region = var.aws_region
}

module "guard" {
  source = "../../modules/guard"

  dry_run             = var.dry_run
  notification_emails = var.notification_emails
  enabled_actions     = var.enabled_actions
  name_prefix         = var.name_prefix
}

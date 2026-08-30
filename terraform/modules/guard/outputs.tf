output "sns_topic_arn" {
  description = "ARN of the SNS topic for Bill Shock Guard alert digests."
  value       = aws_sns_topic.alerts.arn
}

output "sns_topic_name" {
  description = "Name of the SNS topic for Bill Shock Guard alert digests."
  value       = aws_sns_topic.alerts.name
}

output "lambda_name" {
  description = "Name of the Bill Shock Guard scan Lambda function."
  value       = aws_lambda_function.scan.function_name
}

output "lambda_arn" {
  description = "ARN of the Bill Shock Guard scan Lambda function."
  value       = aws_lambda_function.scan.arn
}

output "state_table_name" {
  description = "Name of the DynamoDB state table tracking idle resource lifecycle."
  value       = aws_dynamodb_table.state.name
}

output "state_table_arn" {
  description = "ARN of the DynamoDB state table tracking idle resource lifecycle."
  value       = aws_dynamodb_table.state.arn
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge rule triggering the periodic scan."
  value       = aws_cloudwatch_event_rule.scan_schedule.name
}

output "next_steps" {
  description = "Actionable next steps following deployment of Bill Shock Guard."
  value       = <<-EOT
    Bill Shock Guard has been successfully deployed.

    Next steps:
    1. Confirm the SNS email subscription: Check the inbox for each address configured in 'notification_emails' and click the confirmation link sent by AWS SNS. Subscribers will not receive digests or warnings until confirmed.
    2. Review initial scan: With 'dry_run = true' (the default), inspect the first digest delivered via email/SNS to review flagged idle resources without fear of unwanted mutations.
    3. Protect critical resources: Exempt important resources from automated action by applying the tag '${var.protect_tag_key}=true' (permanent) or '${var.protect_tag_key}=YYYY-MM-DD' (until that date).
    4. Enable mutating actions: Only after reviewing dry-run reports for at least one week, update configuration to set 'dry_run = false' and enable specific desired actions in 'enabled_actions'.
  EOT
}

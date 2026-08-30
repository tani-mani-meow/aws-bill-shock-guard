output "sns_topic_arn" {
  description = "ARN of the SNS alerts topic."
  value       = module.guard.sns_topic_arn
}

output "lambda_name" {
  description = "Name of the Bill Shock Guard scanner Lambda function."
  value       = module.guard.lambda_name
}

output "state_table_name" {
  description = "Name of the DynamoDB state tracking table."
  value       = module.guard.state_table_name
}

output "next_steps" {
  description = "Post-deployment instructions."
  value       = module.guard.next_steps
}

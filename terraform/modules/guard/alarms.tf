resource "aws_sns_topic" "alerts" {
  name = "${var.name_prefix}-alerts"
  tags = local.common_tags
}

resource "aws_sns_topic_subscription" "email_alerts" {
  for_each = toset(var.notification_emails)

  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${var.name_prefix}-lambda-errors"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 21600 # 6 hours (matches scan schedule window)
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Triggered when Bill Shock Guard scan Lambda fails with unhandled errors."

  dimensions = {
    FunctionName = aws_lambda_function.scan.function_name
  }

  alarm_actions = [aws_sns_topic.alerts.arn]

  tags = local.common_tags
}

resource "aws_cloudwatch_log_metric_filter" "scan_errors" {
  name           = "${var.name_prefix}-scan-errors"
  log_group_name = aws_cloudwatch_log_group.lambda_logs.name
  pattern        = "{ ($.event = \"lambda_scan_completed\") && ($.errors_count > 0) }"

  metric_transformation {
    name      = "ScanErrors"
    namespace = "BillShockGuard/${var.name_prefix}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "scan_errors" {
  alarm_name          = "${var.name_prefix}-scan-errors"
  alarm_description   = "Triggered when a scan completes with detector, state, or action errors."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.scan_errors.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.scan_errors.metric_transformation[0].namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = local.common_tags
}

resource "aws_cloudwatch_event_rule" "scan_schedule" {
  name                = "${var.name_prefix}-scan-schedule"
  description         = "Periodic trigger for Bill Shock Guard resource scanner"
  schedule_expression = var.schedule_expression
  state               = var.enabled ? "ENABLED" : "DISABLED"
  tags                = local.common_tags
}

resource "aws_cloudwatch_event_target" "scan_schedule_target" {
  rule      = aws_cloudwatch_event_rule.scan_schedule.name
  target_id = "${var.name_prefix}-scan-lambda-target"
  arn       = aws_lambda_function.scan.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvokeBSG"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scan.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scan_schedule.arn
}

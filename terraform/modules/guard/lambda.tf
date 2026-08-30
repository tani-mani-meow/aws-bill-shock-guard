locals {
  resolved_source_dir = var.lambda_source_dir != "" ? var.lambda_source_dir : "${path.module}/../../../build/lambda"
}

data "archive_file" "lambda_pkg" {
  count       = var.lambda_zip_path == "" ? 1 : 0
  type        = "zip"
  source_dir  = local.resolved_source_dir
  output_path = "${path.module}/build/bill_shock_guard.zip"
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.name_prefix}-scan"
  retention_in_days = 14
  tags              = local.common_tags
}

resource "aws_lambda_function" "scan" {
  function_name = "${var.name_prefix}-scan"
  description   = "Bill Shock Guard periodic cloud waste detector and safety governor"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "bill_shock_guard.handler.scan_handler"
  runtime       = "python3.12"
  architectures = ["arm64"]
  memory_size   = 512
  timeout       = 900

  reserved_concurrent_executions = 1

  filename         = var.lambda_zip_path != "" ? var.lambda_zip_path : data.archive_file.lambda_pkg[0].output_path
  source_code_hash = var.lambda_zip_path != "" ? filebase64sha256(var.lambda_zip_path) : data.archive_file.lambda_pkg[0].output_base64sha256

  environment {
    variables = {
      "BSG_CONFIG" = local.bsg_config_json
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda_logs
  ]

  tags = local.common_tags
}

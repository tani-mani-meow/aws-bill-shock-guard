resource "aws_dynamodb_table" "state" {
  name         = "${var.name_prefix}-state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "key"

  attribute {
    name = "key"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  # Point-in-time recovery is disabled to prevent unnecessary charges (Ephemeral state)
  point_in_time_recovery {
    enabled = false
  }

  # Server-side encryption using default AWS-managed KMS key ($0 cost)
  server_side_encryption {
    enabled = true
  }

  tags = local.common_tags
}

output "ec2_instance_id" {
  description = "Instance ID of the idle EC2 fixture (if enabled)."
  value       = try(aws_instance.idle[0].id, null)
}

output "eip_allocation_id" {
  description = "Allocation ID of the unassociated Elastic IP fixture (if enabled)."
  value       = try(aws_eip.unassociated[0].id, null)
}

output "ebs_volume_id" {
  description = "Volume ID of the unattached EBS fixture (if enabled)."
  value       = try(aws_ebs_volume.unattached[0].id, null)
}

output "nat_gateway_id" {
  description = "ID of the idle NAT Gateway fixture (if enabled)."
  value       = try(aws_nat_gateway.idle[0].id, null)
}

output "alb_arn" {
  description = "ARN of the idle Application Load Balancer fixture (if enabled)."
  value       = try(aws_lb.idle[0].arn, null)
}

output "cost_warning" {
  description = "Cost reminder for active fixtures."
  value       = "FIXTURE NOTICE: Active fixtures incur AWS charges. Remember to destroy after testing."
}

output "destroy_command" {
  description = "Command to teardown and delete all deployed fixture resources immediately."
  value       = "terraform -chdir=terraform/examples/test-fixtures destroy"
}

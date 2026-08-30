variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region where test fixtures will be deployed."
}

variable "create_ec2" {
  type        = bool
  default     = false
  description = "Deploy an idle t3.micro EC2 instance (~$0.0104/hr, ~$7.50/month). Default is false."
}

variable "create_eip" {
  type        = bool
  default     = false
  description = "Deploy an unassociated Elastic IP (~$0.005/hr, ~$3.60/month). Default is false."
}

variable "create_ebs" {
  type        = bool
  default     = false
  description = "Deploy an unattached 1 GiB gp3 EBS volume (~$0.08/month). Default is false."
}

variable "create_nat" {
  type        = bool
  default     = false
  description = "Deploy an idle NAT Gateway (~$0.045/hr, ~$32.40/month + EIP charge). WARNING: Costs real money! Default is false."
}

variable "create_alb" {
  type        = bool
  default     = false
  description = "Deploy an idle Application Load Balancer with 0 targets (~$0.0225/hr, ~$16.20/month). WARNING: Costs real money! Default is false."
}

variable "name_prefix" {
  type        = string
  default     = "bsg-fixture"
  description = "Name prefix applied to all fixture resources for easy identification and cleanup."
}

###############################################################################
# !! LOUD WARNING: HOURLY AWS CHARGES ALERT !!
#
# These test fixtures deliberately deploy IDLE resources into your AWS account
# to verify that Bill Shock Guard detects and governs idle cloud infrastructure.
#
# CERTAIN RESOURCES INCUR REAL HOURLY CHARGES EVERY SINGLE HOUR THEY EXIST:
#   - NAT Gateway:                  ~$0.045 / hour  (~$32.40 / month) + EIP fee
#   - Application Load Balancer:    ~$0.0225 / hour (~$16.20 / month)
#   - Unassociated Elastic IP:      ~$0.005 / hour  (~$3.60 / month)
#   - Running EC2 (t3.micro):       ~$0.0104 / hour (~$7.50 / month)
#   - Unattached EBS (1 GB gp3):    ~$0.08 / GB-month
#
# ALL TOGGLE VARIABLES DEFAULT TO FALSE. ONLY ENABLE WHAT YOU ARE ACTIVELY
# TESTING RIGHT NOW.
#
# ALWAYS DESTROY FIXTURES IMMEDIATELY AFTER TESTING:
#
#   terraform -chdir=terraform/examples/test-fixtures destroy
#
###############################################################################

provider "aws" {
  region = var.aws_region
}

locals {
  need_networking = var.create_ec2 || var.create_nat || var.create_alb
}

data "aws_availability_zones" "available" {
  state = "available"
}

# --- Networking (Created conditionally if EC2, NAT, or ALB is enabled) ---

resource "aws_vpc" "fixtures" {
  count                = local.need_networking ? 1 : 0
  cidr_block           = "10.100.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.name_prefix}-vpc"
    Environment = "test-fixtures"
    ManagedBy   = "Terraform"
  }
}

resource "aws_internet_gateway" "gw" {
  count  = local.need_networking ? 1 : 0
  vpc_id = aws_vpc.fixtures[0].id

  tags = {
    Name        = "${var.name_prefix}-igw"
    Environment = "test-fixtures"
  }
}

resource "aws_subnet" "public_a" {
  count                   = local.need_networking ? 1 : 0
  vpc_id                  = aws_vpc.fixtures[0].id
  cidr_block              = "10.100.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.name_prefix}-subnet-a"
    Environment = "test-fixtures"
  }
}

resource "aws_subnet" "public_b" {
  count                   = local.need_networking ? 1 : 0
  vpc_id                  = aws_vpc.fixtures[0].id
  cidr_block              = "10.100.2.0/24"
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.name_prefix}-subnet-b"
    Environment = "test-fixtures"
  }
}

resource "aws_route_table" "public" {
  count  = local.need_networking ? 1 : 0
  vpc_id = aws_vpc.fixtures[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw[0].id
  }

  tags = {
    Name        = "${var.name_prefix}-public-rt"
    Environment = "test-fixtures"
  }
}

resource "aws_route_table_association" "a" {
  count          = local.need_networking ? 1 : 0
  subnet_id      = aws_subnet.public_a[0].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table_association" "b" {
  count          = local.need_networking ? 1 : 0
  subnet_id      = aws_subnet.public_b[0].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_security_group" "fixtures_sg" {
  count       = local.need_networking ? 1 : 0
  name        = "${var.name_prefix}-sg"
  description = "Security group for test fixture resources"
  vpc_id      = aws_vpc.fixtures[0].id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.name_prefix}-sg"
    Environment = "test-fixtures"
  }
}

# --- Fixture 1: Unassociated Elastic IP ---

resource "aws_eip" "unassociated" {
  count  = var.create_eip ? 1 : 0
  domain = "vpc"

  tags = {
    Name        = "${var.name_prefix}-unassociated-eip"
    Environment = "test-fixtures"
  }
}

# --- Fixture 2: Unattached EBS Volume ---

resource "aws_ebs_volume" "unattached" {
  count             = var.create_ebs ? 1 : 0
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 1
  type              = "gp3"

  tags = {
    Name        = "${var.name_prefix}-unattached-ebs"
    Environment = "test-fixtures"
  }
}

# --- Fixture 3: Idle EC2 Instance ---

data "aws_ami" "amazon_linux" {
  count       = var.create_ec2 ? 1 : 0
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

resource "aws_instance" "idle" {
  count                  = var.create_ec2 ? 1 : 0
  ami                    = data.aws_ami.amazon_linux[0].id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public_a[0].id
  vpc_security_group_ids = [aws_security_group.fixtures_sg[0].id]

  tags = {
    Name        = "${var.name_prefix}-idle-ec2"
    Environment = "test-fixtures"
  }
}

# --- Fixture 4: Idle NAT Gateway ---

resource "aws_eip" "nat" {
  count  = var.create_nat ? 1 : 0
  domain = "vpc"

  tags = {
    Name        = "${var.name_prefix}-nat-eip"
    Environment = "test-fixtures"
  }
}

resource "aws_nat_gateway" "idle" {
  count         = var.create_nat ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public_a[0].id

  tags = {
    Name        = "${var.name_prefix}-idle-nat"
    Environment = "test-fixtures"
  }

  depends_on = [aws_internet_gateway.gw]
}

# --- Fixture 5: Idle Application Load Balancer (0 targets) ---

resource "aws_lb" "idle" {
  count              = var.create_alb ? 1 : 0
  name               = "${var.name_prefix}-idle-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.fixtures_sg[0].id]
  subnets            = [aws_subnet.public_a[0].id, aws_subnet.public_b[0].id]

  # No target groups or listeners created: LB remains completely idle with zero traffic

  tags = {
    Name        = "${var.name_prefix}-idle-alb"
    Environment = "test-fixtures"
  }
}

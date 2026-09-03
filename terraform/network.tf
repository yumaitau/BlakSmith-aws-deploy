# Network isolation.
#
# Three tiers. The data tier has NO route to the internet — not "blocked by a security group",
# no route at all. A misconfigured security group is a one-line mistake; a subnet with no NAT
# and no gateway cannot exfiltrate regardless of what runs in it.

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${local.name}-vpc" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.name}-igw" }
}

# Public: load balancer and NAT only. Nothing that touches data is ever placed here.
resource "aws_subnet" "edge" {
  count                   = var.az_count
  vpc_id                  = aws_vpc.main.id
  availability_zone       = local.azs[count.index]
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  map_public_ip_on_launch = false

  tags = { Name = "${local.name}-edge-${local.azs[count.index]}", Tier = "edge" }
}

resource "aws_subnet" "application" {
  count             = var.az_count
  vpc_id            = aws_vpc.main.id
  availability_zone = local.azs[count.index]
  cidr_block        = cidrsubnet(var.vpc_cidr, 6, count.index + 1)

  tags = { Name = "${local.name}-app-${local.azs[count.index]}", Tier = "application" }
}

resource "aws_subnet" "data" {
  count             = var.az_count
  vpc_id            = aws_vpc.main.id
  availability_zone = local.azs[count.index]
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 20)

  tags = { Name = "${local.name}-data-${local.azs[count.index]}", Tier = "data" }
}

resource "aws_eip" "nat" {
  count  = local.is_prod ? var.az_count : 1
  domain = "vpc"
  tags   = { Name = "${local.name}-nat-${count.index}" }
}

# One NAT per AZ in production: a single NAT is cheaper but makes every AZ depend on one,
# which turns a single-AZ failure into a total outage.
resource "aws_nat_gateway" "main" {
  count         = local.is_prod ? var.az_count : 1
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.edge[count.index].id
  depends_on    = [aws_internet_gateway.main]

  tags = { Name = "${local.name}-nat-${count.index}" }
}

resource "aws_route_table" "edge" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${local.name}-edge" }
}

resource "aws_route_table_association" "edge" {
  count          = var.az_count
  subnet_id      = aws_subnet.edge[count.index].id
  route_table_id = aws_route_table.edge.id
}

resource "aws_route_table" "application" {
  count  = var.az_count
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[local.is_prod ? count.index : 0].id
  }

  tags = { Name = "${local.name}-app-${count.index}" }
}

resource "aws_route_table_association" "application" {
  count          = var.az_count
  subnet_id      = aws_subnet.application[count.index].id
  route_table_id = aws_route_table.application[count.index].id
}

# No default route. This is the control, not a security group rule.
resource "aws_route_table" "data" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.name}-data" }
}

resource "aws_route_table_association" "data" {
  count          = var.az_count
  subnet_id      = aws_subnet.data[count.index].id
  route_table_id = aws_route_table.data.id
}

# --- Flow logs ---------------------------------------------------------------------------
#
# The only way to answer "what talked to what" after the fact — needed precisely when the
# network is not behaving as designed.

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/${local.name}/flow-logs"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.logs.arn
}

resource "aws_iam_role" "flow_logs" {
  name               = "${local.name}-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
}

data "aws_iam_policy_document" "flow_logs_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "write-flow-logs"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
      ]
      Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
    }]
  })
}

resource "aws_flow_log" "main" {
  vpc_id                   = aws_vpc.main.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60
}

# --- VPC endpoints -------------------------------------------------------------------------
#
# Keep AWS control-plane traffic inside the VPC. KMS matters most: every envelope decrypt is
# a KMS call, and routing those over the public internet would undo much of what the
# encryption is for.

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"

  route_table_ids = concat(
    aws_route_table.application[*].id,
    [aws_route_table.data.id],
  )

  tags = { Name = "${local.name}-s3" }
}

resource "aws_security_group" "endpoints" {
  name        = "${local.name}-endpoints"
  description = "VPC interface endpoints"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from within the VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = { Name = "${local.name}-endpoints" }
}

locals {
  interface_endpoints = [
    "kms",
    "secretsmanager",
    "logs",
    "ecr.api",
    "ecr.dkr",
    "sts",
    "ssm",
  ]
}

resource "aws_vpc_endpoint" "interface" {
  for_each = toset(local.interface_endpoints)

  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.application[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true

  tags = { Name = "${local.name}-${each.value}" }
}

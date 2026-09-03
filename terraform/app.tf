# The application tier: Fargate behind a WAF-protected, TLS-only load balancer.
#
# Everything here is gated on `local.deploy_app`, so the infrastructure can be provisioned and
# reviewed before an image exists.

resource "aws_ecs_cluster" "main" {
  count = local.deploy_app ? 1 : 0
  name  = local.name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_cloudwatch_log_group" "app" {
  count             = local.deploy_app ? 1 : 0
  name              = "/aws/ecs/${local.name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.logs.arn
}

# Two roles, not one. The execution role pulls the image and writes logs; the task role is
# what the application code itself can do. Merging them would let the running container pull
# arbitrary images.
resource "aws_iam_role" "task_execution" {
  count              = local.deploy_app ? 1 : 0
  name               = "${local.name}-task-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "task_execution" {
  count      = local.deploy_app ? 1 : 0
  role       = aws_iam_role.task_execution[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "task_execution_secrets" {
  statement {
    sid       = "ReadRuntimeSecrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_db_instance.main.master_user_secret[0].secret_arn, aws_secretsmanager_secret.application.arn]
  }

  statement {
    sid       = "DecryptRuntimeSecrets"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.logs.arn]
  }
}

resource "aws_iam_role_policy" "task_execution_secrets" {
  count  = local.deploy_app ? 1 : 0
  name   = "runtime-secrets"
  role   = aws_iam_role.task_execution[0].id
  policy = data.aws_iam_policy_document.task_execution_secrets.json
}

resource "aws_iam_role" "task" {
  count              = local.deploy_app ? 1 : 0
  name               = "${local.name}-task"
  description        = "BlakSmith application runtime identity"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

data "aws_iam_policy_document" "task" {
  statement {
    sid = "AwsMarketplaceContainerLicense"
    actions = [
      "license-manager:CheckoutLicense",
      "license-manager:GetLicense",
      "license-manager:CheckInLicense",
      "license-manager:ExtendLicenseConsumption",
      "license-manager:ListReceivedLicenses",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "Documents"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.documents.arn, "${aws_s3_bucket.documents.arn}/*"]
  }

  statement {
    sid       = "EvidenceAppendOnly"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
  }

  # Object Lock already refuses these. Denying them here means the attempt fails before it is
  # made, and appears as an explicit deny in CloudTrail rather than as a silent no-op.
  statement {
    sid    = "EvidenceNeverMutable"
    effect = "Deny"
    actions = [
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
      "s3:PutObjectRetention",
      "s3:BypassGovernanceRetention",
    ]
    resources = ["${aws_s3_bucket.evidence.arn}/*"]
  }

  statement {
    sid       = "EnvelopeEncryption"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = [aws_kms_key.application_data.arn, aws_kms_key.storage.arn]
  }

  # The application wraps and unwraps data keys. It must never be able to destroy one —
  # cryptographic erasure belongs to the key custodian role, behind MFA.
  statement {
    sid    = "NeverDestroyKeys"
    effect = "Deny"
    actions = [
      "kms:ScheduleKeyDeletion",
      "kms:DisableKey",
      "kms:DeleteAlias",
      "kms:PutKeyPolicy",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "ReadDatabaseSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_db_instance.main.master_user_secret[0].secret_arn, aws_secretsmanager_secret.application.arn]
  }
}

resource "aws_iam_role_policy" "task" {
  count  = local.deploy_app ? 1 : 0
  name   = "runtime"
  role   = aws_iam_role.task[0].id
  policy = data.aws_iam_policy_document.task.json
}

resource "aws_security_group" "service" {
  count       = local.deploy_app ? 1 : 0
  name        = "${local.name}-service"
  description = "BlakSmith tasks"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "From the load balancer"
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb[0].id]
  }

  egress {
    description = "Outbound for KMS, Secrets Manager and ECR"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name}-service" }
}

# Completes the database security group: ingress only from the application tier.
resource "aws_vpc_security_group_ingress_rule" "database_from_service" {
  count                        = local.deploy_app ? 1 : 0
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = aws_security_group.service[0].id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "Postgres from the application tier"
}

resource "aws_ecs_task_definition" "app" {
  count                    = local.deploy_app ? 1 : 0
  family                   = local.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 1024
  memory                   = 2048
  execution_role_arn       = aws_iam_role.task_execution[0].arn
  task_role_arn            = aws_iam_role.task[0].arn

  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }

  container_definitions = jsonencode([{
    name      = "web"
    image     = var.web_image_uri
    essential = true

    # The container writes nothing to its own filesystem. Removes a whole class of
    # persistence for an attacker who achieves code execution.
    readonlyRootFilesystem = true

    portMappings = [{ containerPort = 3000, protocol = "tcp" }]

    environment = [
      { name = "NODE_ENV", value = "production" },
      { name = "AWS_REGION", value = var.region },
      { name = "APP_URL", value = var.public_url },
      { name = "BETTER_AUTH_URL", value = var.public_url },
      { name = "BETTER_AUTH_TRUSTED_PROXIES", value = var.vpc_cidr },
      { name = "BLAKSMITH_DB_HOST", value = aws_db_instance.main.address },
      { name = "BLAKSMITH_DB_PORT", value = tostring(aws_db_instance.main.port) },
      { name = "BLAKSMITH_DB_NAME", value = aws_db_instance.main.db_name },
      { name = "BLAKSMITH_DB_APP_USER", value = "blaksmith_app" },
      { name = "BLAKSMITH_KEY_PROVIDER", value = "aws-kms" },
      { name = "BLAKSMITH_KMS_ALIAS_PREFIX", value = "alias/${local.name}" },
      { name = "BLAKSMITH_STORAGE", value = "s3" },
      { name = "BLAKSMITH_S3_BUCKET", value = aws_s3_bucket.documents.id },
      { name = "BLAKSMITH_S3_KMS_KEY_ID", value = aws_kms_key.storage.arn },
      { name = "BLAKSMITH_EVIDENCE_BUCKET", value = aws_s3_bucket.evidence.id },
    ]

    secrets = [
      {
        name      = "BLAKSMITH_DB_OWNER_USER"
        valueFrom = "${aws_db_instance.main.master_user_secret[0].secret_arn}:username::"
      },
      {
        name      = "BLAKSMITH_DB_OWNER_PASSWORD"
        valueFrom = "${aws_db_instance.main.master_user_secret[0].secret_arn}:password::"
      },
      {
        name      = "BLAKSMITH_DB_APP_PASSWORD"
        valueFrom = "${aws_secretsmanager_secret.application.arn}:app_database_password::"
      },
      {
        name      = "BETTER_AUTH_SECRET"
        valueFrom = "${aws_secretsmanager_secret.application.arn}:better_auth_secret::"
      },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.app[0].name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "blaksmith"
      }
    }

    healthCheck = {
      command     = ["CMD-SHELL", "node -e \"fetch('http://localhost:3000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))\""]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 60
    }
  }])

  depends_on = [aws_secretsmanager_secret_version.application]
}

resource "aws_ecs_task_definition" "worker" {
  count                    = local.deploy_worker ? 1 : 0
  family                   = "${local.name}-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.task_execution[0].arn
  task_role_arn            = aws_iam_role.task[0].arn

  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }

  container_definitions = jsonencode([{
    name                   = "worker"
    image                  = var.worker_image_uri
    essential              = true
    readonlyRootFilesystem = true

    environment = [
      { name = "NODE_ENV", value = "production" },
      { name = "AWS_REGION", value = var.region },
      { name = "HOME", value = "/tmp" },
      { name = "AUTOINGEST_JOBS", value = "[]" },
      { name = "BLAKSMITH_DB_HOST", value = aws_db_instance.main.address },
      { name = "BLAKSMITH_DB_PORT", value = tostring(aws_db_instance.main.port) },
      { name = "BLAKSMITH_DB_NAME", value = aws_db_instance.main.db_name },
      { name = "BLAKSMITH_DB_APP_USER", value = "blaksmith_app" },
      { name = "BLAKSMITH_KEY_PROVIDER", value = "aws-kms" },
      { name = "BLAKSMITH_KMS_ALIAS_PREFIX", value = "alias/${local.name}" },
      { name = "BLAKSMITH_STORAGE", value = "s3" },
      { name = "BLAKSMITH_S3_BUCKET", value = aws_s3_bucket.documents.id },
      { name = "BLAKSMITH_S3_KMS_KEY_ID", value = aws_kms_key.storage.arn },
      { name = "BLAKSMITH_EVIDENCE_BUCKET", value = aws_s3_bucket.evidence.id },
    ]

    secrets = [
      {
        name      = "BLAKSMITH_DB_OWNER_USER"
        valueFrom = "${aws_db_instance.main.master_user_secret[0].secret_arn}:username::"
      },
      {
        name      = "BLAKSMITH_DB_OWNER_PASSWORD"
        valueFrom = "${aws_db_instance.main.master_user_secret[0].secret_arn}:password::"
      },
      {
        name      = "BLAKSMITH_DB_APP_PASSWORD"
        valueFrom = "${aws_secretsmanager_secret.application.arn}:app_database_password::"
      },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.app[0].name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "worker"
      }
    }
  }])

  depends_on = [aws_secretsmanager_secret_version.application]
}

resource "aws_ecs_service" "app" {
  count           = local.deploy_app ? 1 : 0
  name            = local.name
  cluster         = aws_ecs_cluster.main[0].id
  task_definition = aws_ecs_task_definition.app[0].arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  # Keep full capacity during a deployment. The ECS default halves throughput mid-roll, which
  # for an API fronting land registry queries is a self-inflicted outage.
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  network_configuration {
    subnets = aws_subnet.application[*].id
    # Private subnets, no public IP. Reachable only through the load balancer.
    assign_public_ip = false
    security_groups  = [aws_security_group.service[0].id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app[0].arn
    container_name   = "web"
    container_port   = 3000
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  # No shell into a container holding land title data.
  enable_execute_command = false

  depends_on = [aws_lb_listener.https]
}

resource "aws_ecs_service" "worker" {
  count           = local.deploy_worker ? 1 : 0
  name            = "${local.name}-worker"
  cluster         = aws_ecs_cluster.main[0].id
  task_definition = aws_ecs_task_definition.worker[0].arn
  desired_count   = var.worker_desired_count
  launch_type     = "FARGATE"

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  network_configuration {
    subnets          = aws_subnet.application[*].id
    assign_public_ip = false
    security_groups  = [aws_security_group.service[0].id]
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = false
  }

  enable_execute_command = false
}

# --- Load balancer ------------------------------------------------------------------------------------

resource "aws_security_group" "alb" {
  count       = local.deploy_app ? 1 : 0
  name        = "${local.name}-alb"
  description = "BlakSmith load balancer"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from the internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP, redirected to HTTPS"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "To the application tier"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = { Name = "${local.name}-alb" }
}

resource "aws_lb" "main" {
  count              = local.deploy_app ? 1 : 0
  name               = local.name
  load_balancer_type = "application"
  internal           = false
  subnets            = aws_subnet.edge[*].id
  security_groups    = [aws_security_group.alb[0].id]

  drop_invalid_header_fields = true
  enable_deletion_protection = local.is_prod

  access_logs {
    bucket  = aws_s3_bucket.access_logs.id
    prefix  = "alb"
    enabled = true
  }
}

resource "aws_lb_target_group" "app" {
  count       = local.deploy_app ? 1 : 0
  name        = "${local.name}-app"
  port        = 3000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  deregistration_delay = 30

  health_check {
    path                = "/api/health"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "https" {
  count             = local.deploy_app ? 1 : 0
  load_balancer_arn = aws_lb.main[0].arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = var.certificate_arn
  # TLS 1.3 with a 1.2 floor; no CBC ciphers.
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app[0].arn
  }
}

# Redirect rather than serve: an HTTP listener returning content would let a client send a
# session cookie in the clear before the redirect ever happened.
resource "aws_lb_listener" "http_redirect" {
  count             = local.deploy_app ? 1 : 0
  load_balancer_arn = aws_lb.main[0].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# --- WAF -----------------------------------------------------------------------------------------------

resource "aws_wafv2_web_acl" "main" {
  count = local.deploy_app ? 1 : 0
  name  = local.name
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  dynamic "rule" {
    for_each = {
      AWSManagedRulesCommonRuleSet          = 0
      AWSManagedRulesKnownBadInputsRuleSet  = 1
      AWSManagedRulesSQLiRuleSet            = 2
      AWSManagedRulesAmazonIpReputationList = 3
    }

    content {
      name     = rule.key
      priority = rule.value

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          vendor_name = "AWS"
          name        = rule.key
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.key
        sampled_requests_enabled   = true
      }
    }
  }

  # Blunt but effective against credential stuffing and scraping of a public API.
  rule {
    name     = "RateLimit"
    priority = 4

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "BlakSmithWebAcl"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "main" {
  count        = local.deploy_app ? 1 : 0
  resource_arn = aws_lb.main[0].arn
  web_acl_arn  = aws_wafv2_web_acl.main[0].arn
}

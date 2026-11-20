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

  # Revoking a sharing package must remove every version of it and of BlakSmith's custody
  # copy of its key: the documents bucket is versioned, so a plain delete only hides them.
  statement {
    sid       = "SharingPackageRevocation"
    actions   = ["s3:ListBucketVersions"]
    resources = [aws_s3_bucket.documents.arn]
  }

  statement {
    sid       = "SharingPackagePurge"
    actions   = ["s3:DeleteObjectVersion"]
    resources = ["${aws_s3_bucket.documents.arn}/*tenants/*/sharing/*"]
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

  # Tenant, custodian, and s38 CMKs. The app calls kmsAliasForScope under the same
  # prefix injected as BLAKSMITH_KMS_ALIAS_PREFIX. A prefix-wide alias grant would also
  # match infrastructure keys, so those aliases are excluded. The ARN grant above stays;
  # application_data is not the envelope root.
  statement {
    sid       = "TenantEnvelopeKeys"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["arn:aws:kms:${var.region}:${local.account_id}:key/*"]

    condition {
      test     = "ForAnyValue:StringLike"
      variable = "kms:ResourceAliases"
      values   = ["alias/${local.name}/*"]
    }

    condition {
      test     = "ForAllValues:StringNotLike"
      variable = "kms:ResourceAliases"
      values = [
        "alias/${local.name}/database",
        "alias/${local.name}/storage",
        "alias/${local.name}/logs",
        "alias/${local.name}/secrets",
        "alias/${local.name}/application-data",
        "alias/${local.name}/applicationdata",
      ]
    }
  }

  # Tenant onboarding creates the tenant's CMK and alias (#139, one CMK per tenant). The
  # role may create a key only when tagged as a tenant envelope key, may not bypass the
  # policy lockout check, and may alias it only under the tenant prefix. It still cannot
  # schedule deletion, disable, or change the policy afterwards (NeverDestroyKeys).
  dynamic "statement" {
    for_each = var.tenant_key_self_provisioning ? [1] : []
    content {
      sid       = "CreateTenantEnvelopeKey"
      actions   = ["kms:CreateKey", "kms:TagResource"]
      resources = ["*"]
      condition {
        test     = "StringEquals"
        variable = "aws:RequestTag/Purpose"
        values   = ["tenant-envelope"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.tenant_key_self_provisioning ? [1] : []
    content {
      sid     = "AliasAndRotateTenantEnvelopeKey"
      actions = ["kms:CreateAlias", "kms:EnableKeyRotation", "kms:DescribeKey"]
      resources = [
        "arn:aws:kms:${var.region}:${local.account_id}:alias/${local.name}/*",
        "arn:aws:kms:${var.region}:${local.account_id}:key/*",
      ]
    }
  }

  statement {
    sid       = "NeverBypassKeyPolicyLockout"
    effect    = "Deny"
    actions   = ["kms:CreateKey"]
    resources = ["*"]
    condition {
      test     = "Bool"
      variable = "kms:BypassPolicyLockoutSafetyCheck"
      values   = ["true"]
    }
  }

  # Customer-held keys (#140): the app reaches a client's CMK only by assuming that
  # tenant's role, tagged with the tenant id. The tenant role's trust policy checks the tag.
  statement {
    sid       = "AssumeCustomerTenantRoles"
    actions   = ["sts:AssumeRole", "sts:TagSession"]
    resources = ["arn:aws:iam::${local.account_id}:role/${local.name}-tenant-*"]
  }

  # Escrow (#141): deposit-only. The application may wrap a data key under a tenant's escrow
  # CMK in the escrow account and can never read one back. The Deny is structural: it holds
  # even if an escrow key policy were misconfigured to grant Decrypt.
  dynamic "statement" {
    for_each = var.escrow_account_id == "" ? [] : [1]
    content {
      sid       = "EscrowDepositOnly"
      actions   = ["kms:Encrypt"]
      resources = ["arn:aws:kms:${var.region}:${var.escrow_account_id}:key/*"]
    }
  }

  dynamic "statement" {
    for_each = var.escrow_account_id == "" ? [] : [1]
    content {
      sid    = "EscrowNeverReadable"
      effect = "Deny"
      actions = [
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:CreateGrant",
        "kms:GenerateDataKey*",
      ]
      resources = ["arn:aws:kms:*:${var.escrow_account_id}:key/*"]
    }
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

  # Long-running tasks read the RDS-managed owner secret per new connection, so a rotation
  # needs no restart (packages/db/src/db-secret.ts). Only that secret: the application secret
  # (app-role password, Better Auth secret, bootstrap password) is injected by the execution
  # role at start and is not readable by application code.
  statement {
    sid       = "ReadRotatingDatabaseSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_db_instance.main.master_user_secret[0].secret_arn]
  }

  statement {
    sid       = "DecryptRotatingDatabaseSecret"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.logs.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "task" {
  count  = local.deploy_app ? 1 : 0
  name   = "runtime"
  role   = aws_iam_role.task[0].id
  policy = data.aws_iam_policy_document.task.json
}

# One role per customer-keyed tenant (#140). The client's key policy names this role, not
# the shared task role, so a confused-deputy bug serving tenant B cannot use tenant A's
# grant. Assumable only by the task role, and only with a session tag for this tenant.
resource "aws_iam_role" "customer_tenant" {
  for_each             = local.deploy_app ? var.customer_key_tenants : {}
  name                 = "${local.name}-tenant-${each.key}"
  description          = "Data-plane use of tenant ${each.key}'s customer-held CMK"
  max_session_duration = 3600
  assume_role_policy   = data.aws_iam_policy_document.customer_tenant_assume[each.key].json
}

data "aws_iam_policy_document" "customer_tenant_assume" {
  for_each = local.deploy_app ? var.customer_key_tenants : {}

  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.task[0].arn]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/tenantId"
      values   = [each.key]
    }
  }
}

data "aws_iam_policy_document" "customer_tenant" {
  for_each = local.deploy_app ? var.customer_key_tenants : {}

  statement {
    sid = "CustomerKeyDataPlane"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
    ]
    resources = [each.value]

    # Same binding the client's key policy applies, enforced on our side as well.
    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:tenantId"
      values   = [each.key]
    }
  }

  statement {
    sid       = "NeverAdministerCustomerKey"
    effect    = "Deny"
    actions   = ["kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:PutKeyPolicy", "kms:CreateGrant"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "customer_tenant" {
  for_each = local.deploy_app ? var.customer_key_tenants : {}
  name     = "customer-key"
  role     = aws_iam_role.customer_tenant[each.key].id
  policy   = data.aws_iam_policy_document.customer_tenant[each.key].json
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

  # Same security group, not a second network. Web and the REST API both own /nodes,
  # so the API is not a second ALB target. Tasks in this group can call it on 8080.
  ingress {
    description = "API from the application tier"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    self        = true
  }

  # HTTPS only: KMS, Secrets Manager, ECR, STS, SSM and CloudWatch Logs are reached through
  # interface endpoints or the S3 gateway endpoint, all on 443. DNS goes to the VPC resolver,
  # which security groups do not filter.
  egress {
    description = "HTTPS to AWS APIs and endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description     = "PostgreSQL to the data tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.database.id]
  }

  egress {
    description = "Private API within the application tier"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    self        = true
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

# Shared by the long-running web, API and worker tasks. Asserted by tests/app.tftest.hcl.
#
# Owner credentials: the username plus the rotating secret's ARN, never the password. The
# pool reads the secret per new connection (BLAKSMITH_DB_OWNER_SECRET_ARN), so RDS rotating the
# master password does not break new connections. Bootstrap values are migrate-only.
locals {
  runtime_environment = [
    { name = "NODE_ENV", value = "production" },
    { name = "AWS_REGION", value = var.region },
    { name = "HOME", value = "/tmp" },
    { name = "APP_URL", value = var.public_url },
    { name = "BETTER_AUTH_URL", value = var.public_url },
    { name = "BETTER_AUTH_TRUSTED_PROXIES", value = var.vpc_cidr },
    # IdP-initiated SAML stays off; it would apply to every SAML provider.
    { name = "BETTER_AUTH_SAML_ALLOW_IDP_INITIATED", value = "false" },
    { name = "BLAKSMITH_DB_HOST", value = aws_db_instance.main.address },
    { name = "BLAKSMITH_DB_PORT", value = tostring(aws_db_instance.main.port) },
    { name = "BLAKSMITH_DB_NAME", value = aws_db_instance.main.db_name },
    { name = "BLAKSMITH_DB_OWNER_USER", value = aws_db_instance.main.username },
    { name = "BLAKSMITH_DB_OWNER_SECRET_ARN", value = aws_db_instance.main.master_user_secret[0].secret_arn },
    { name = "BLAKSMITH_DB_APP_USER", value = "blaksmith_app" },
    { name = "DB_POOL_MAX", value = tostring(var.db_pool_max) },
    { name = "BLAKSMITH_KEY_PROVIDER", value = "aws-kms" },
    { name = "BLAKSMITH_KMS_ALIAS_PREFIX", value = "alias/${local.name}" },
    { name = "BLAKSMITH_ESCROW", value = var.escrow_account_id == "" ? "off" : "aws-kms" },
    { name = "BLAKSMITH_ESCROW_ACCOUNT_ID", value = var.escrow_account_id },
    { name = "BLAKSMITH_ESCROW_REGION", value = var.region },
    { name = "BLAKSMITH_STORAGE", value = "s3" },
    { name = "BLAKSMITH_S3_BUCKET", value = aws_s3_bucket.documents.id },
    { name = "BLAKSMITH_S3_KMS_KEY_ID", value = aws_kms_key.storage.arn },
    { name = "BLAKSMITH_EVIDENCE_BUCKET", value = aws_s3_bucket.evidence.id },
  ]

  runtime_secrets = [
    {
      name      = "BLAKSMITH_DB_APP_PASSWORD"
      valueFrom = "${aws_secretsmanager_secret.application.arn}:app_database_password::"
    },
    {
      name      = "BETTER_AUTH_SECRET"
      valueFrom = "${aws_secretsmanager_secret.application.arn}:better_auth_secret::"
    },
  ]
}

# One-shot migrate (+ optional first-owner bootstrap). Not an ECS service — operators
# RunTask this family before updating the web service. Web no longer migrates on start.
resource "aws_ecs_task_definition" "migrate" {
  count                    = local.deploy_migrate ? 1 : 0
  family                   = "${local.name}-migrate"
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

  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([{
    name                   = "migrate"
    image                  = var.migrate_image_uri
    essential              = true
    readonlyRootFilesystem = true

    mountPoints = [{
      sourceVolume  = "tmp"
      containerPath = "/tmp"
      readOnly      = false
    }]

    environment = [
      { name = "NODE_ENV", value = "production" },
      { name = "AWS_REGION", value = var.region },
      { name = "HOME", value = "/tmp" },
      { name = "TSX_DISABLE_CACHE", value = "1" },
      { name = "BLAKSMITH_BOOTSTRAP_TENANT_SLUG", value = var.bootstrap_tenant_slug },
      { name = "BLAKSMITH_BOOTSTRAP_TENANT_NAME", value = var.bootstrap_tenant_name },
      { name = "BLAKSMITH_BOOTSTRAP_OWNER_EMAIL", value = var.bootstrap_owner_email },
      { name = "BLAKSMITH_BOOTSTRAP_OWNER_NAME", value = var.bootstrap_owner_name },
      { name = "BLAKSMITH_DB_HOST", value = aws_db_instance.main.address },
      { name = "BLAKSMITH_DB_PORT", value = tostring(aws_db_instance.main.port) },
      { name = "BLAKSMITH_DB_NAME", value = aws_db_instance.main.db_name },
      { name = "BLAKSMITH_DB_APP_USER", value = "blaksmith_app" },
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
        name      = "BLAKSMITH_BOOTSTRAP_OWNER_PASSWORD"
        valueFrom = "${aws_secretsmanager_secret.application.arn}:bootstrap_owner_password::"
      },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.app[0].name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "migrate"
      }
    }
  }])

  depends_on = [aws_secretsmanager_secret_version.application]
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

  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([{
    name      = "web"
    image     = var.web_image_uri
    essential = true

    # The container writes nothing to its own filesystem. Removes a whole class of
    # persistence for an attacker who achieves code execution.
    readonlyRootFilesystem = true

    mountPoints = [{
      sourceVolume  = "tmp"
      containerPath = "/tmp"
      readOnly      = false
    }]

    portMappings = [{ containerPort = 3000, protocol = "tcp" }]

    environment = local.runtime_environment

    secrets = local.runtime_secrets

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.app[0].name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "blaksmith"
      }
    }

    # ALB already probes /api/health. A second in-container `node -e` probe
    # fails on the read-only rootfs and ECS replaces otherwise-healthy tasks.
  }])

  depends_on = [aws_secretsmanager_secret_version.application]
}

# REST API. Same task role, subnets, and security group as web. Not an ALB target:
# the web UI and this API both serve /nodes.
resource "aws_ecs_task_definition" "api" {
  count                    = local.deploy_api ? 1 : 0
  family                   = "${local.name}-api"
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

  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([{
    name                   = "api"
    image                  = var.api_image_uri
    essential              = true
    readonlyRootFilesystem = true

    mountPoints = [{
      sourceVolume  = "tmp"
      containerPath = "/tmp"
      readOnly      = false
    }]

    portMappings = [{ containerPort = 8080, protocol = "tcp" }]

    environment = concat(local.runtime_environment, [
      { name = "API_PORT", value = "8080" },
    ])

    secrets = local.runtime_secrets

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.app[0].name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "api"
      }
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

  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([{
    name                   = "worker"
    image                  = var.worker_image_uri
    essential              = true
    readonlyRootFilesystem = true

    mountPoints = [{
      sourceVolume  = "tmp"
      containerPath = "/tmp"
      readOnly      = false
    }]

    environment = concat(local.runtime_environment, [
      { name = "TSX_DISABLE_CACHE", value = "1" },
    ])

    secrets = local.runtime_secrets

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
  health_check_grace_period_seconds  = 180

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

resource "aws_ecs_service" "api" {
  count           = local.deploy_api ? 1 : 0
  name            = "${local.name}-api"
  cluster         = aws_ecs_cluster.main[0].id
  task_definition = aws_ecs_task_definition.api[0].arn
  desired_count   = var.desired_count
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
    rollback = true
  }

  enable_execute_command = false
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
    rollback = true
  }

  enable_execute_command = false
}

# --- Load balancer ------------------------------------------------------------------------------------

resource "aws_security_group" "alb" {
  #checkov:skip=CKV_AWS_260:Port 80 only reaches the http_redirect listener, which returns a 301 to HTTPS and serves no content
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
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = { Name = "${local.name}-alb" }
}

resource "aws_lb" "main" {
  #checkov:skip=CKV2_AWS_76:KnownBadInputs, the Log4j rule group, is attached; this check also demands AnonymousIpList, which is unrelated to Log4j and would block legitimate VPN users
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

  depends_on = [aws_s3_bucket_policy.access_logs]
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

  # AWS managed rule groups, written out rather than generated so scanners can see that
  # KnownBadInputs (which covers Log4j JNDI lookups) is attached.
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 0

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesKnownBadInputsRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesSQLiRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesSQLiRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAmazonIpReputationList"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesAmazonIpReputationList"
      sampled_requests_enabled   = true
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

# WAF decisions are the only record of what the edge blocked. Credentials and session cookies
# are redacted before they reach the log.
resource "aws_cloudwatch_log_group" "waf" {
  count             = local.deploy_app ? 1 : 0
  name              = "aws-waf-logs-${local.name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.logs.arn
}

resource "aws_wafv2_web_acl_logging_configuration" "main" {
  count                   = local.deploy_app ? 1 : 0
  resource_arn            = aws_wafv2_web_acl.main[0].arn
  log_destination_configs = [aws_cloudwatch_log_group.waf[0].arn]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }
}

resource "aws_wafv2_web_acl_association" "main" {
  count        = local.deploy_app ? 1 : 0
  resource_arn = aws_lb.main[0].arn
  web_acl_arn  = aws_wafv2_web_acl.main[0].arn
}

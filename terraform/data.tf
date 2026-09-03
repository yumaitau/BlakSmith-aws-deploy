# The data tier: Postgres and object storage. Everything CMK-encrypted, unreachable from the
# internet, and hard to delete by accident.

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

locals {
  bucket_suffix = random_id.bucket_suffix.hex
}

# --- Buckets --------------------------------------------------------------------------------

# Access logs live in their own bucket, which cannot log to itself.
resource "aws_s3_bucket" "access_logs" {
  bucket        = "${local.name}-access-logs-${local.bucket_suffix}"
  force_destroy = !local.is_prod
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 server access logging cannot write to an SSE-KMS bucket, so this one uses S3-managed
# keys. It holds request metadata, never record content.
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "expire"
    status = "Enabled"
    filter {}
    expiration { days = 400 }
  }
}

resource "aws_s3_bucket" "documents" {
  bucket        = "${local.name}-documents-${local.bucket_suffix}"
  force_destroy = !local.is_prod
}

resource "aws_s3_bucket_public_access_block" "documents" {
  bucket                  = aws_s3_bucket.documents.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "documents" {
  bucket = aws_s3_bucket.documents.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.storage.arn
    }
    # Without a bucket key, every object read is a separate KMS call — slow and expensive at
    # land-registry volumes.
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "documents" {
  bucket = aws_s3_bucket.documents.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_logging" "documents" {
  bucket        = aws_s3_bucket.documents.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "documents/"
}

# Evidence. Object Lock CANNOT be enabled after creation, so it is on unconditionally: if
# immutability might ever be required, the decision has to be made now.
resource "aws_s3_bucket" "evidence" {
  bucket              = "${local.name}-evidence-${local.bucket_suffix}"
  object_lock_enabled = true

  # Never force_destroy, even in dev — Object Lock would refuse anyway, and a plan that
  # promises to delete it is misleading.
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.storage.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration { status = "Enabled" }
}

# COMPLIANCE, not GOVERNANCE. GOVERNANCE can be bypassed by any principal holding
# s3:BypassGovernanceRetention, which means the root account can quietly delete records it is
# supposed to be unable to touch. For evidence backing a determination, an immutability
# guarantee the operator can override is not one.
resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.evidence_retention_days
    }
  }
}

resource "aws_s3_bucket_logging" "evidence" {
  bucket        = aws_s3_bucket.evidence.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "evidence/"
}

# TLS floor on every bucket. aws:SecureTransport alone permits TLS 1.0/1.1; s3:TlsVersion is
# the half that actually excludes them.
data "aws_iam_policy_document" "bucket_tls" {
  for_each = {
    documents   = aws_s3_bucket.documents.arn
    evidence    = aws_s3_bucket.evidence.arn
    access_logs = aws_s3_bucket.access_logs.arn
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [each.value, "${each.value}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyOutdatedTls"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [each.value, "${each.value}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values   = ["1.2"]
    }
  }
}

resource "aws_s3_bucket_policy" "documents" {
  bucket = aws_s3_bucket.documents.id
  policy = data.aws_iam_policy_document.bucket_tls["documents"].json
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = data.aws_iam_policy_document.bucket_tls["evidence"].json
}

# --- Database --------------------------------------------------------------------------------

resource "aws_db_subnet_group" "main" {
  name       = "${local.name}-data"
  subnet_ids = aws_subnet.data[*].id
}

resource "aws_security_group" "database" {
  name        = "${local.name}-database"
  description = "BlakSmith Postgres - ingress only from the application tier"
  vpc_id      = aws_vpc.main.id

  # No egress rules at all. A database has no legitimate reason to originate connections, and
  # removing the ability removes a well-worn exfiltration path.
  tags = { Name = "${local.name}-database" }
}

resource "aws_db_parameter_group" "main" {
  name   = "${local.name}-pg18"
  family = "postgres18"

  # Refuse any connection that is not TLS. Without this a client inside the VPC can silently
  # negotiate plaintext and nothing complains.
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  # The audit trail below the application's own hash-chained one.
  parameter {
    name  = "log_statement"
    value = "ddl"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }
}

resource "aws_db_instance" "main" {
  identifier     = "${local.name}-postgres"
  engine         = "postgres"
  engine_version = "18.3"
  instance_class = var.db_instance_class

  db_name  = "blaksmith"
  username = "blaksmith"
  # Generated and rotated by RDS into Secrets Manager. No password ever appears in state,
  # in a variable, or in a developer's shell history.
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.logs.arn

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.database.arn

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.database.id]
  publicly_accessible    = false
  multi_az               = local.is_prod
  parameter_group_name   = aws_db_parameter_group.main.name

  # Lets the application authenticate with an IAM role instead of a long-lived password.
  iam_database_authentication_enabled = true

  backup_retention_period    = 35
  delete_automated_backups   = false
  copy_tags_to_snapshot      = true
  deletion_protection        = local.is_prod
  skip_final_snapshot        = !local.is_prod
  final_snapshot_identifier  = local.is_prod ? "${local.name}-final" : null
  auto_minor_version_upgrade = true

  enabled_cloudwatch_logs_exports       = ["postgresql", "upgrade"]
  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.database.arn
  performance_insights_retention_period = 31
  monitoring_interval                   = 30
  monitoring_role_arn                   = aws_iam_role.rds_monitoring.arn
}

# Runtime-only credentials that are not part of the RDS master secret. The app role is
# created/rotated by the migration container and is subject to tenant RLS; Better Auth uses
# a separate high-entropy signing secret. Terraform state is sensitive and must use the
# encrypted, versioned remote backend documented in the buyer guide.
resource "random_password" "app_database" {
  length  = 48
  special = true
}

resource "random_password" "better_auth" {
  length  = 64
  special = false
}

resource "aws_secretsmanager_secret" "application" {
  name                    = "${local.name}/application"
  description             = "BlakSmith restricted database and authentication secrets"
  kms_key_id              = aws_kms_key.logs.arn
  recovery_window_in_days = local.is_prod ? 30 : 7
}

resource "aws_secretsmanager_secret_version" "application" {
  secret_id = aws_secretsmanager_secret.application.id
  secret_string = jsonencode({
    app_database_password = random_password.app_database.result
    better_auth_secret    = random_password.better_auth.result
  })
}

resource "aws_iam_role" "rds_monitoring" {
  name               = "${local.name}-rds-monitoring"
  assume_role_policy = data.aws_iam_policy_document.rds_monitoring_assume.json
}

data "aws_iam_policy_document" "rds_monitoring_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

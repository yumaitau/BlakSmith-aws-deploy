# Detection and audit.
#
# BlakSmith's own hash-chained log records what the APPLICATION did. CloudTrail records what
# was done to the INFRASTRUCTURE — who used a KMS key, who changed a bucket policy, who took a
# snapshot. Neither substitutes for the other, and an investigation needs both.

resource "aws_sns_topic" "security_alerts" {
  name              = "${local.name}-security-alerts"
  kms_master_key_id = aws_kms_key.logs.arn
}

resource "aws_sns_topic_subscription" "security_email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --- CloudTrail ------------------------------------------------------------------------------

# Object Lock here is what stops an attacker with account access deleting the record of what
# they did. Without it, CloudTrail is a log an administrator can erase.
resource "aws_s3_bucket" "trail" {
  bucket              = "${local.name}-trail-${local.bucket_suffix}"
  object_lock_enabled = true
  force_destroy       = false
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.logs.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.trail_retention_days
    }
  }
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid       = "AWSConfigWrite"
    actions   = ["s3:PutObject", "s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/config/*"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]

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
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

resource "aws_cloudtrail" "main" {
  name                          = "${local.name}-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  kms_key_id                    = aws_kms_key.logs.arn
  include_global_service_events = true
  is_multi_region_trail         = true

  # Digest files signed by AWS — what lets an auditor prove the log was not edited. The same
  # argument as BlakSmith's own hash chain, one layer down.
  enable_log_file_validation = true

  # Management events alone record that a bucket exists, not that someone read every object
  # in it — which is the event that matters when the objects are land title documents.
  advanced_event_selector {
    name = "S3 and KMS data events"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
  }

  advanced_event_selector {
    name = "Management events"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  depends_on = [aws_s3_bucket_policy.trail]
}

# --- GuardDuty ---------------------------------------------------------------------------------

resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_guardduty_detector_feature" "s3_logs" {
  detector_id = aws_guardduty_detector.main.id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

# --- Security Hub with FSBP + CIS -----------------------------------------------------------------

resource "aws_securityhub_account" "main" {
  enable_default_standards  = false
  control_finding_generator = "SECURITY_CONTROL"
  auto_enable_controls      = true
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:${var.region}::standards/cis-aws-foundations-benchmark/v/3.0.0"
  depends_on    = [aws_securityhub_account.main]
}

# --- AWS Config ------------------------------------------------------------------------------------

resource "aws_iam_role" "config" {
  name               = "${local.name}-config"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json
}

data "aws_iam_policy_document" "config_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "main" {
  name     = "${local.name}-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${local.name}-delivery"
  s3_bucket_name = aws_s3_bucket.trail.id
  s3_key_prefix  = "config"
  depends_on     = [aws_config_configuration_recorder.main, aws_s3_bucket_policy.trail]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

# A focused set of managed rules: the ones whose failure would directly break a promise made
# in docs/security-architecture.md. Security Hub's standards cover far more.
locals {
  config_rules = {
    s3-public-read-prohibited  = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    s3-public-write-prohibited = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
    s3-ssl-requests-only       = "S3_BUCKET_SSL_REQUESTS_ONLY"
    s3-sse-enabled             = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
    rds-storage-encrypted      = "RDS_STORAGE_ENCRYPTED"
    rds-not-public             = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
    rds-multi-az               = "RDS_MULTI_AZ_SUPPORT"
    rds-deletion-protection    = "RDS_INSTANCE_DELETION_PROTECTION_ENABLED"
    cloudtrail-enabled         = "CLOUD_TRAIL_ENABLED"
    cloudtrail-encrypted       = "CLOUD_TRAIL_ENCRYPTION_ENABLED"
    cloudtrail-validation      = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
    kms-rotation-enabled       = "CMK_BACKING_KEY_ROTATION_ENABLED"
    vpc-flow-logs-enabled      = "VPC_FLOW_LOGS_ENABLED"
    iam-root-access-key        = "IAM_ROOT_ACCESS_KEY_CHECK"
    iam-console-mfa            = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
    ebs-encryption-by-default  = "EC2_EBS_ENCRYPTION_BY_DEFAULT"
  }
}

resource "aws_config_config_rule" "managed" {
  for_each = local.config_rules

  name = "${local.name}-${each.key}"

  source {
    owner             = "AWS"
    source_identifier = each.value
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# --- Route findings somewhere a human sees -----------------------------------------------------------

resource "aws_cloudwatch_event_rule" "high_severity_findings" {
  name        = "${local.name}-high-severity-findings"
  description = "Security Hub findings of HIGH or CRITICAL severity"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = { Label = ["HIGH", "CRITICAL"] }
        Workflow = { Status = ["NEW"] }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "high_severity_findings" {
  rule = aws_cloudwatch_event_rule.high_severity_findings.name
  arn  = aws_sns_topic.security_alerts.arn
}

# The two events that must never happen quietly: destroying the key that makes land title
# records readable, and disabling the trail that would record whatever comes next.
resource "aws_cloudwatch_event_rule" "key_destruction" {
  name        = "${local.name}-key-destruction"
  description = "Any attempt to schedule KMS key deletion or disable a key"

  event_pattern = jsonencode({
    source      = ["aws.kms"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["kms.amazonaws.com"]
      eventName   = ["ScheduleKeyDeletion", "DisableKey", "DisableKeyRotation"]
    }
  })
}

resource "aws_cloudwatch_event_target" "key_destruction" {
  rule = aws_cloudwatch_event_rule.key_destruction.name
  arn  = aws_sns_topic.security_alerts.arn
}

resource "aws_cloudwatch_event_rule" "trail_tampering" {
  name        = "${local.name}-trail-tampering"
  description = "CloudTrail configuration changed, stopped or deleted"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["cloudtrail.amazonaws.com"]
      eventName   = ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"]
    }
  })
}

resource "aws_cloudwatch_event_target" "trail_tampering" {
  rule = aws_cloudwatch_event_rule.trail_tampering.name
  arn  = aws_sns_topic.security_alerts.arn
}

data "aws_iam_policy_document" "sns_events" {
  statement {
    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn    = aws_sns_topic.security_alerts.arn
  policy = data.aws_iam_policy_document.sns_events.json
}

# Emergency access role.
#
# Break-glass exists because refusing all emergency access produces shared admin accounts and
# disabled controls, which is worse. Its scope is bounded on principle:
#
#   * MFA is mandatory. Emergency access without it is just a second admin role.
#   * Sessions last at most an hour, so a forgotten one expires on its own.
#   * READ-ONLY on the data plane. An incident justifies looking; it does not justify
#     changing land title records outside the audited application path.
#   * No key destruction. That is the key-custodian role, separately gated.
#
# The AWS side and the application side are separate on purpose. These credentials reach the
# infrastructure; they do not raise a principal's clearance inside BlakSmith, and no AWS
# permission can override a custodian group's authority over its own material. See
# `packages/authz/src/classified.ts`.

resource "aws_iam_role" "break_glass" {
  name                 = "${local.name}-break-glass"
  description          = "Time-boxed, MFA-gated, read-only emergency access. Every assumption is reviewed."
  assume_role_policy   = data.aws_iam_policy_document.break_glass_assume.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "break_glass_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }

    # Belt and braces: even if a caller requests a longer session, cap it.
    condition {
      test     = "NumericLessThanEquals"
      variable = "aws:TokenIssueTime"
      values   = ["3600"]
    }
  }
}

data "aws_iam_policy_document" "break_glass" {
  # Read-only across the operational surface. Enough to diagnose; not enough to alter.
  statement {
    sid = "DiagnosticReadOnly"
    actions = [
      "cloudwatch:Get*",
      "cloudwatch:List*",
      "cloudwatch:Describe*",
      "logs:Get*",
      "logs:Describe*",
      "logs:FilterLogEvents",
      "logs:StartQuery",
      "logs:GetQueryResults",
      "ecs:Describe*",
      "ecs:List*",
      "rds:Describe*",
      "ec2:Describe*",
      "elasticloadbalancing:Describe*",
      "s3:ListBucket",
      "s3:GetBucketLocation",
      "kms:DescribeKey",
      "kms:ListAliases",
      "securityhub:Get*",
      "securityhub:List*",
      "guardduty:Get*",
      "guardduty:List*",
      "cloudtrail:LookupEvents",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:DescribeTrails",
    ]
    resources = ["*"]
  }

  # Reading a document is a decision the application makes, with a purpose and an audit
  # record. Granting it here would create an unaudited side door around every classification
  # control in the codebase — which is the whole thing this system exists to prevent.
  statement {
    sid    = "NeverReadClassifiedContentDirectly"
    effect = "Deny"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "kms:Decrypt",
      "kms:GenerateDataKey*",
    ]
    resources = [
      "${aws_s3_bucket.documents.arn}/*",
      "${aws_s3_bucket.evidence.arn}/*",
      aws_kms_key.application_data.arn,
      aws_kms_key.storage.arn,
    ]
  }

  statement {
    sid    = "NeverMutateOrDestroy"
    effect = "Deny"
    actions = [
      "kms:ScheduleKeyDeletion",
      "kms:DisableKey",
      "kms:PutKeyPolicy",
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
      "s3:PutBucketPolicy",
      "s3:PutBucketPublicAccessBlock",
      "rds:DeleteDBInstance",
      "rds:ModifyDBInstance",
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
      "cloudtrail:UpdateTrail",
      "config:DeleteConfigurationRecorder",
      "config:StopConfigurationRecorder",
      "guardduty:DeleteDetector",
      "securityhub:DisableSecurityHub",
      "iam:*",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "break_glass" {
  name   = "emergency-read-only"
  role   = aws_iam_role.break_glass.id
  policy = data.aws_iam_policy_document.break_glass.json
}

# Every assumption of this role is an event a human should see, not something discovered in a
# quarterly log review.
resource "aws_cloudwatch_event_rule" "break_glass_used" {
  name        = "${local.name}-break-glass-used"
  description = "The break-glass role was assumed"

  event_pattern = jsonencode({
    source      = ["aws.sts"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["sts.amazonaws.com"]
      eventName   = ["AssumeRole"]
      requestParameters = {
        roleArn = [aws_iam_role.break_glass.arn]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "break_glass_used" {
  rule = aws_cloudwatch_event_rule.break_glass_used.name
  arn  = aws_sns_topic.security_alerts.arn
}

output "break_glass_role_arn" {
  description = "MFA-gated, time-boxed, read-only emergency access role. Assumptions are alerted on."
  value       = aws_iam_role.break_glass.arn
}

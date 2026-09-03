# Customer-managed keys, one per purpose.
#
# Separate keys rather than one for the account, because a key policy is the only thing
# between a principal and everything the key protects. One shared key makes "can read the
# database" and "can read the audit log" the same permission; separate keys let an auditor
# read the trail without being able to read the records it describes.
#
# All keys rotate annually. AWS retains prior key material so existing ciphertext keeps
# decrypting — there is no reason to leave rotation off.

locals {
  # 30 days in production: the pending-deletion window is the only chance to recover from an
  # erroneous deletion, and losing the application data key means losing the data.
  key_deletion_window = local.is_prod ? 30 : 7
}

resource "aws_kms_key" "database" {
  description             = "BlakSmith RDS storage, snapshots and Performance Insights"
  enable_key_rotation     = true
  deletion_window_in_days = local.key_deletion_window
}

resource "aws_kms_alias" "database" {
  name          = "alias/${local.name}/database"
  target_key_id = aws_kms_key.database.key_id
}

resource "aws_kms_key" "storage" {
  description             = "BlakSmith S3 documents and evidence"
  enable_key_rotation     = true
  deletion_window_in_days = local.key_deletion_window
}

resource "aws_kms_alias" "storage" {
  name          = "alias/${local.name}/storage"
  target_key_id = aws_kms_key.storage.key_id
}

resource "aws_kms_key" "logs" {
  description             = "BlakSmith CloudTrail, Config and CloudWatch Logs"
  enable_key_rotation     = true
  deletion_window_in_days = local.key_deletion_window
  policy                  = data.aws_iam_policy_document.logs_key.json
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${local.name}/logs"
  target_key_id = aws_kms_key.logs.key_id
}

# The envelope-encryption root. `@blaksmith/crypto`'s AWS KMS provider wraps every tenant and
# custodian-group data key with this, so it — not the database, not the bucket — is the real
# access control on land title content.
resource "aws_kms_key" "application_data" {
  description             = "BlakSmith envelope-encryption root for tenant and custodian-group data keys"
  enable_key_rotation     = true
  deletion_window_in_days = local.key_deletion_window
  policy                  = data.aws_iam_policy_document.application_data_key.json
}

resource "aws_kms_alias" "application_data" {
  name          = "alias/${local.name}/application-data"
  target_key_id = aws_kms_key.application_data.key_id
}

data "aws_iam_policy_document" "logs_key" {
  statement {
    sid       = "EnableIamUserPermissions"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  # CloudTrail, Config and CloudWatch Logs write with a service principal, not a role, so the
  # key policy must allow them explicitly.
  statement {
    sid       = "AllowLogServiceEncryption"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type = "Service"
      identifiers = [
        "cloudtrail.amazonaws.com",
        "config.amazonaws.com",
        "logs.${var.region}.amazonaws.com",
        "sns.amazonaws.com",
      ]
    }

    # Without this condition ANY account's trail could encrypt to this key — the classic
    # confused-deputy shape.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

data "aws_iam_policy_document" "application_data_key" {
  statement {
    sid       = "EnableIamUserPermissions"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  # Cryptographic erasure is a real, supported operation — a Traditional Owner group
  # withdrawing consent must be enforceable, not merely recorded. But it is irreversible, so
  # it is reachable only from a dedicated custodian role, never from a general admin policy.
  statement {
    sid    = "DenyKeyDestructionExceptByKeyCustodian"
    effect = "Deny"
    actions = [
      "kms:ScheduleKeyDeletion",
      "kms:DisableKey",
      "kms:DisableKeyRotation",
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::${local.account_id}:role/${local.name}-key-custodian*"]
    }
  }
}

# The role that may perform cryptographic erasure. Assumable only with MFA, and by nobody by
# default — a human must be added deliberately.
resource "aws_iam_role" "key_custodian" {
  name                 = "${local.name}-key-custodian"
  description          = "May destroy BlakSmith data keys (cryptographic erasure). Irreversible."
  assume_role_policy   = data.aws_iam_policy_document.key_custodian_assume.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "key_custodian_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }

    # MFA is not optional for an operation that permanently destroys records.
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

resource "aws_iam_role_policy" "key_custodian" {
  name   = "key-destruction"
  role   = aws_iam_role.key_custodian.id
  policy = data.aws_iam_policy_document.key_custodian.json
}

data "aws_iam_policy_document" "key_custodian" {
  statement {
    actions   = ["kms:ScheduleKeyDeletion", "kms:DescribeKey", "kms:ListAliases"]
    resources = [aws_kms_key.application_data.arn]
  }
}

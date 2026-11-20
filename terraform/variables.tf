variable "region" {
  description = "AWS region to deploy into. Constrained by allowed_regions."
  type        = string
  default     = "ap-southeast-2"
}

variable "allowed_regions" {
  description = <<-EOT
    Data residency allowlist. A plan targeting anything outside this list fails.

    Defaults to ap-southeast-2 because Indigenous land title records held in Australia are
    normally required to remain onshore. Change it deliberately, not incidentally.
  EOT
  type        = list(string)
  default     = ["ap-southeast-2"]
}

variable "environment" {
  description = "Deployment environment. 'prod' enables retention, deletion protection and multi-AZ."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "buyer", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, buyer, prod."
  }
}

variable "name_prefix" {
  description = "Prefix for resource names. Must be globally unique enough for S3 bucket names."
  type        = string
  default     = "blaksmith"
}

variable "vpc_cidr" {
  description = "CIDR for the VPC."
  type        = string
  default     = "10.40.0.0/16"
}

variable "az_count" {
  description = "Availability zones to span. Two is the minimum for RDS Multi-AZ; four is the maximum before application /22 subnets overlap data subnets."
  type        = number
  default     = 3

  validation {
    condition     = var.az_count >= 2 && var.az_count <= 4
    error_message = "az_count must be between 2 and 4 so RDS can run Multi-AZ without subnet CIDR overlap."
  }
}

variable "evidence_retention_days" {
  description = <<-EOT
    S3 Object Lock retention for evidence, in days, in COMPLIANCE mode.

    Once written, an object cannot be altered or deleted for this long by anyone — including
    the account root. Default is 7 years. Object Lock cannot be enabled after bucket
    creation, so this decision is made once.
  EOT
  type        = number
  default     = 2555
}

variable "trail_retention_days" {
  description = "Object Lock retention for CloudTrail logs, in days."
  type        = number
  default     = 2555
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.m6g.large"
}

variable "db_allocated_storage" {
  description = "Initial RDS storage in GB. Autoscales up to db_max_allocated_storage."
  type        = number
  default     = 100
}

variable "db_max_allocated_storage" {
  description = "Ceiling for RDS storage autoscaling in GB."
  type        = number
  default     = 1000
}

variable "alert_email" {
  description = "Email for high-severity security findings. Subscription must be confirmed manually."
  type        = string
  default     = ""
}

variable "web_image_uri" {
  description = "BlakSmith web image from AWS Marketplace ECR. Leave empty to provision infrastructure only."
  type        = string
  default     = ""
}

variable "api_image_uri" {
  description = "BlakSmith API image. Required when web_image_uri is set."
  type        = string
  default     = ""
}

variable "worker_image_uri" {
  description = "Optional BlakSmith worker image from AWS Marketplace ECR. Omit AUTOINGEST_JOBS; an empty array is rejected by the worker."
  type        = string
  default     = ""
}

variable "migrate_image_uri" {
  description = "BlakSmith migrate one-shot image. Required when web_image_uri is set; run via ECS RunTask before rolling the web service."
  type        = string
  default     = ""
}

variable "public_url" {
  description = "Public HTTPS origin covered by certificate_arn, for example https://blaksmith.example.gov.au."
  type        = string
  default     = ""
}

variable "bootstrap_tenant_slug" {
  description = "Slug for the first tenant created during licensed startup."
  type        = string
  default     = "default"
}

variable "bootstrap_tenant_name" {
  description = "Display name for the first tenant."
  type        = string
  default     = "BlakSmith"
}

variable "bootstrap_owner_email" {
  description = "Email address for the first tenant owner. Required when deploying the web image."
  type        = string
  default     = ""
}

variable "bootstrap_owner_name" {
  description = "Display name for the first tenant owner."
  type        = string
  default     = "Account owner"
}

variable "certificate_arn" {
  description = <<-EOT
    ACM certificate ARN for the HTTPS listener.

    Required whenever web_image_uri is set. There is no HTTP fallback: a listener without TLS
    would put land title data on the wire in plaintext.
  EOT
  type        = string
  default     = ""
}

variable "desired_count" {
  description = "Number of web tasks and of API tasks."
  type        = number
  default     = 2
}

variable "db_pool_max" {
  description = <<-EOT
    postgres.js pool size per pool (DB_POOL_MAX). Each web, API and worker task opens one owner
    pool and one app-role pool, so the worst-case backend count is
    (2 x desired_count + worker_desired_count) x 2 x db_pool_max. Keep it under the instance's
    max_connections with room for migrate and admin sessions.
  EOT
  type        = number
  default     = 10

  validation {
    condition     = var.db_pool_max >= 1 && var.db_pool_max <= 50
    error_message = "db_pool_max must be between 1 and 50."
  }
}

variable "worker_desired_count" {
  description = "Number of background worker tasks. Start at zero, then enable after the web service is healthy."
  type        = number
  default     = 0
}

locals {
  is_prod        = var.environment == "prod"
  name           = "${var.name_prefix}-${var.environment}"
  account_id     = data.aws_caller_identity.current.account_id
  deploy_app     = var.web_image_uri != ""
  deploy_api     = local.deploy_app && var.api_image_uri != ""
  deploy_worker  = local.deploy_app && var.worker_image_uri != ""
  deploy_migrate = local.deploy_app && var.migrate_image_uri != ""
  azs            = slice(data.aws_availability_zones.available.names, 0, var.az_count)
}

data "aws_availability_zones" "available" {
  #checkov:skip=CKV_AWS_394:Only the first az_count zones are used, so a new zone does not change the result; pinning zone IDs would reshuffle existing subnets and the database subnet group
  state = "available"

  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

# Fails the plan if an application deployment is requested without TLS. There is no HTTP
# fallback anywhere in this configuration; this makes the omission a plan-time error rather
# than something discovered after deployment.
resource "terraform_data" "require_tls" {
  count = local.deploy_app ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.certificate_arn != "" && can(regex("^https://[^/]+$", var.public_url))
      error_message = "certificate_arn and a bare-origin HTTPS public_url are required when web_image_uri is set."
    }


    precondition {
      condition     = var.worker_desired_count == 0 || var.worker_image_uri != ""
      error_message = "worker_image_uri is required when worker_desired_count is greater than zero."
    }

    precondition {
      condition     = var.api_image_uri != ""
      error_message = "api_image_uri is required when web_image_uri is set."
    }

    precondition {
      condition     = var.migrate_image_uri != ""
      error_message = "migrate_image_uri is required when web_image_uri is set; run the migrate task before rolling web and API."
    }

    precondition {
      condition     = can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.bootstrap_owner_email))
      error_message = "bootstrap_owner_email must be a valid email address when web_image_uri is set."
    }
  }
}

variable "customer_key_tenants" {
  description = "Customer-keyed tenants: map of tenant id to the client's CMK ARN. Creates role <name>-tenant-<id> for the client's key policy to grant (#140)."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for id, arn in var.customer_key_tenants :
      can(regex("^[A-Za-z0-9._:-]+$", id)) && can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/.+$", arn))
    ])
    error_message = "Keys must be tenant ids without path characters; values must be full KMS key ARNs (aliases do not work cross-account)."
  }
}

variable "tenant_key_self_provisioning" {
  description = "Let the application create a vendor tenant CMK + alias when a tenant is created (#139). It still cannot delete, disable or re-policy keys."
  type        = bool
  default     = true
}

variable "escrow_account_id" {
  description = "BlakSmith escrow AWS account (#141). Empty disables escrow deposits. The task role gets Encrypt only, with an explicit Deny on Decrypt/ReEncrypt."
  type        = string
  default     = ""

  validation {
    condition     = var.escrow_account_id == "" || can(regex("^[0-9]{12}$", var.escrow_account_id))
    error_message = "escrow_account_id must be empty or a 12-digit account id."
  }
}

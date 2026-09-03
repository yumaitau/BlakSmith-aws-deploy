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
  description = "Availability zones to span. Two is the minimum for RDS Multi-AZ."
  type        = number
  default     = 3

  validation {
    condition     = var.az_count >= 2
    error_message = "az_count must be at least 2 so the database can run Multi-AZ."
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

variable "worker_image_uri" {
  description = "Optional BlakSmith worker image from AWS Marketplace ECR."
  type        = string
  default     = ""
}

variable "public_url" {
  description = "Public HTTPS origin covered by certificate_arn, for example https://blaksmith.example.gov.au."
  type        = string
  default     = ""
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
  description = "Number of web application tasks."
  type        = number
  default     = 2
}

variable "worker_desired_count" {
  description = "Number of background worker tasks. Start at zero, then enable after the web service is healthy."
  type        = number
  default     = 0
}

locals {
  is_prod       = var.environment == "prod"
  name          = "${var.name_prefix}-${var.environment}"
  account_id    = data.aws_caller_identity.current.account_id
  deploy_app    = var.web_image_uri != ""
  deploy_worker = local.deploy_app && var.worker_image_uri != ""
  azs           = slice(data.aws_availability_zones.available.names, 0, var.az_count)
}

data "aws_availability_zones" "available" {
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
  }
}

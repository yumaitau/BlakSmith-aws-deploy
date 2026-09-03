terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # State holds resource metadata and, for some resources, secret material. It belongs in a
  # bucket with versioning, SSE-KMS and a lock table — not on a laptop. Configure with
  # `terraform init -backend-config=...` so the bucket name is not baked into the repo.
  backend "s3" {}
}

provider "aws" {
  region = var.region

  # Data residency, enforced by the provider rather than trusted. A plan targeting a region
  # outside the allowlist fails in `terraform plan`, before anything is created — the same
  # guarantee the CDK app's RegionGuard gives, expressed the Terraform way.
  #
  # Every resource is tagged so that an account-wide query can find anything holding
  # classified material without relying on naming conventions.
  default_tags {
    tags = {
      Application        = "BlakSmith"
      Environment        = var.environment
      DataClassification = "protected"
      ManagedBy          = "terraform"
    }
  }
}

# Fails the plan when var.region is outside var.allowed_regions. `precondition` on a data
# source runs during plan, so the mistake surfaces before any API call creates anything.
data "aws_region" "current" {
  lifecycle {
    postcondition {
      condition     = contains(var.allowed_regions, self.region)
      error_message = "Region ${self.region} is outside the data residency allowlist ${join(", ", var.allowed_regions)}. Deploy to a permitted region, or change allowed_regions deliberately."
    }
  }
}

data "aws_caller_identity" "current" {}

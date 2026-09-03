![BlakSmith](assets/blaksmith-readme-banner.png)

# BlakSmith AWS Marketplace deployment

Public buyer deployment artifacts for the BlakSmith AWS Marketplace container product.
Subscribe to the limited or public listing before deployment; the publisher does not host or
receive your protected data.

The product images live in AWS Marketplace ECR:

```text
709825985650.dkr.ecr.us-east-1.amazonaws.com/yuma-it/blaksmith-web
709825985650.dkr.ecr.us-east-1.amazonaws.com/yuma-it/blaksmith-worker
709825985650.dkr.ecr.us-east-1.amazonaws.com/yuma-it/blaksmith-api
709825985650.dkr.ecr.us-east-1.amazonaws.com/yuma-it/blaksmith-migrate
709825985650.dkr.ecr.us-east-1.amazonaws.com/yuma-it/blaksmith-mcp
```

Use only the immutable `sha-<commit>` tag or digest shown in the Marketplace delivery
instructions. Never use `latest`. The Terraform stack deploys the web app and can enable the
worker after the web service has completed database bootstrap.

## What Terraform creates

- A three-AZ VPC with public load-balancer, private application, and private data subnets
- TLS-only Application Load Balancer, AWS WAF, and ECS Fargate on ARM64
- RDS PostgreSQL 18 with encrypted storage, backups, logs, and an RLS-restricted app role
- KMS-encrypted document and immutable evidence buckets
- CloudTrail, GuardDuty, Security Hub, AWS Config, alarms, and optional SNS alerts
- Secrets Manager credentials and least-privilege ECS execution/task roles
- Fail-closed AWS Marketplace License Manager checks in every Marketplace image

## Prerequisites

- An AWS Marketplace subscription to BlakSmith
- Terraform 1.9 or newer and AWS credentials for the buyer account
- An ACM certificate in the deployment Region and a public hostname you control
- A versioned, encrypted S3 Terraform backend; state contains generated secret material

## Deploy

```sh
git clone https://github.com/yumaitau/BlakSmith-aws-deploy.git
cd BlakSmith-aws-deploy/terraform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:

1. Set `web_image_uri` and `worker_image_uri` to existing Marketplace ECR SHA tags.
2. Set `public_url` to the HTTPS origin covered by `certificate_arn`.
3. Choose `environment = "buyer"` for a limited-offer test or `"prod"` for retained,
   deletion-protected production resources.
4. Set the bootstrap tenant and owner fields to the real first administrator.
5. Leave `worker_desired_count = 0` for the first apply.

Configure your private state backend, then deploy:

```sh
terraform init \
  -backend-config="bucket=YOUR-TERRAFORM-STATE-BUCKET" \
  -backend-config="key=blaksmith/terraform.tfstate" \
  -backend-config="region=ap-southeast-2" \
  -backend-config="encrypt=true"
terraform plan -var-file=terraform.tfvars -out=tfplan
terraform apply tfplan
terraform output load_balancer_dns
```

Point the `public_url` hostname at `load_balancer_dns`. After the web service is healthy and
`GET /api/health` succeeds, set `worker_desired_count = 1` and apply again.

The licensed web startup provisions the specified owner idempotently. Retrieve the generated
one-time password without printing any other secret fields, sign in, and rotate it immediately:

```sh
secret_arn="$(terraform output -raw application_secret_arn)"
aws secretsmanager get-secret-value --secret-id "$secret_arn" \
  --query SecretString --output text \
  | jq -r '.bootstrap_owner_password'
```

No default user, static password, buyer-supplied Marketplace product code, or licensing bypass
is accepted by Terraform.

## Runtime licensing

The Marketplace image embeds product SKU `prod-udrpgy4kdzwva` and contract dimension
`standard_workspace` at build time. At startup it consumes one contract entitlement through
AWS License Manager `CheckoutLicense`; it then revalidates periodically. Missing credentials,
permissions, subscription, or entitlement makes the process exit non-zero before serving.

## Health and logs

- Health: `GET /api/health`
- ECS log group: `/aws/ecs/<name_prefix>-<environment>`
- Expected startup event: `AWS Marketplace entitlement validated`

## Cost and teardown

AWS bills the buyer directly for ECS, NAT gateways, ALB, RDS, S3, KMS, WAF, Secrets Manager,
CloudWatch, and security services. Production enables Multi-AZ RDS and long retention. Review
the Terraform plan and current AWS pricing before apply.

Evidence objects use S3 Object Lock COMPLIANCE mode and cannot be deleted before their
retention expires, including by the root user. Destroy non-production test stacks before
writing evidence, or expect the evidence bucket to remain.

```sh
terraform destroy -var-file=terraform.tfvars
```

## Support

Open a support request at https://github.com/yumaitau/BlakSmith-aws-deploy/issues.

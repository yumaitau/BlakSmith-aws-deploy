# Terraform module

This root module is the supported ECS Fargate deployment for the BlakSmith AWS Marketplace
container product. See the repository README for the deployment sequence.

Important operating constraints:

- Keep `terraform.tfvars` and state private. Generated database and auth secrets are sensitive.
- `public_url` must be a bare HTTPS origin whose hostname is covered by `certificate_arn`.
- Image values must be existing AWS Marketplace ECR SHA tags or digests, never `latest`.
- Run the first apply with `worker_desired_count = 0`; enable the worker after web health passes.
- Set the bootstrap owner fields to a real administrator; their generated initial password is
  stored in the application secret and must be rotated after first sign-in.
- The task role contains AWS License Manager consumption permissions. Removing them makes the
  Marketplace containers fail closed.
- `environment = "prod"` enables deletion protection and Multi-AZ RDS. `"buyer"` is intended
  for limited-offer validation and still keeps all application and database traffic private.
- Evidence Object Lock is always COMPLIANCE mode. Retained evidence can prevent full teardown.

The web container performs idempotent extension setup, creates or rotates the restricted
`blaksmith_app` database role, applies migrations, and only then starts Next.js. Runtime data
access uses that role under tenant RLS; owner credentials remain limited to control-plane and
migration work.

output "vpc_id" {
  description = "VPC hosting the deployment."
  value       = aws_vpc.main.id
}

output "database_endpoint" {
  description = "Postgres endpoint. Reachable only from the application tier."
  value       = aws_db_instance.main.endpoint
}

output "database_secret_arn" {
  description = "Secrets Manager ARN holding the master credentials. RDS rotates it."
  value       = aws_db_instance.main.master_user_secret[0].secret_arn
}

output "application_secret_arn" {
  description = "Secrets Manager ARN holding the restricted database and Better Auth secrets."
  value       = aws_secretsmanager_secret.application.arn
}

output "documents_bucket" {
  description = "Bucket for classified documents. Payloads are sealed before upload."
  value       = aws_s3_bucket.documents.id
}

output "evidence_bucket" {
  description = "Evidence bucket. Object Lock COMPLIANCE - immutable for evidence_retention_days."
  value       = aws_s3_bucket.evidence.id
}

output "application_data_key_arn" {
  description = "Envelope-encryption root key. Point BLAKSMITH_KMS_ALIAS_PREFIX at the matching alias prefix so the application derives per-tenant and per-custodian-group keys beneath it."
  value       = aws_kms_key.application_data.arn
}

output "key_custodian_role_arn" {
  description = <<-EOT
    The only role that may destroy data keys (cryptographic erasure). MFA required, and no
    principal is trusted to assume it until one is added deliberately.
  EOT
  value       = aws_iam_role.key_custodian.arn
}

output "security_alerts_topic_arn" {
  description = "SNS topic receiving high-severity findings and key/trail tampering events."
  value       = aws_sns_topic.security_alerts.arn
}

output "load_balancer_dns" {
  description = "Public DNS name of the load balancer, when the application is deployed."
  value       = local.deploy_app ? aws_lb.main[0].dns_name : null
}

output "task_role_arn" {
  description = "Application runtime identity, when the application is deployed."
  value       = local.deploy_app ? aws_iam_role.task[0].arn : null
}

output "web_service_name" {
  description = "ECS web service name."
  value       = local.deploy_app ? aws_ecs_service.app[0].name : null
}

output "worker_service_name" {
  description = "ECS worker service name, when configured."
  value       = local.deploy_worker ? aws_ecs_service.worker[0].name : null
}

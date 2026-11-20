# Offline assertions on the application tier (#151, #155). Mocked providers: nothing is
# created and no AWS credentials are needed.
#
#   terraform init -backend=false && terraform test
#
# Asserts that every long-running task (web, API, worker) carries the env and secrets the
# application needs, that none of them carries an owner password or a bootstrap secret, that
# migrate is a one-shot task definition with no service, and that Postgres admits the
# application security group.

mock_provider "aws" {
  # Mocked JSON must still parse as a policy for the resources that validate it.
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  # Resources whose ARN feeds another resource's validated ARN argument.
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:ap-southeast-2:111122223333:key/mock" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/mock" }
  }
  mock_resource "aws_sns_topic" {
    defaults = { arn = "arn:aws:sns:ap-southeast-2:111122223333:mock" }
  }
  mock_resource "aws_lb" {
    defaults = { arn = "arn:aws:elasticloadbalancing:ap-southeast-2:111122223333:loadbalancer/app/mock/1" }
  }
  mock_resource "aws_lb_target_group" {
    defaults = { arn = "arn:aws:elasticloadbalancing:ap-southeast-2:111122223333:targetgroup/mock/1" }
  }
  mock_resource "aws_wafv2_web_acl" {
    defaults = { arn = "arn:aws:wafv2:ap-southeast-2:111122223333:regional/webacl/mock/1" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::mock" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:ap-southeast-2:111122223333:log-group:mock" }
  }
  mock_resource "aws_ecs_cluster" {
    defaults = { arn = "arn:aws:ecs:ap-southeast-2:111122223333:cluster/mock" }
  }

  override_data {
    target = data.aws_availability_zones.available
    values = {
      names = ["ap-southeast-2a", "ap-southeast-2b", "ap-southeast-2c"]
    }
  }

  override_data {
    target = data.aws_region.current
    values = {
      region = "ap-southeast-2"
      name   = "ap-southeast-2"
    }
  }

  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "111122223333"
    }
  }

  override_data {
    target = data.aws_elb_service_account.main
    values = {
      arn = "arn:aws:iam::783225319266:root"
    }
  }
}

mock_provider "random" {}

override_resource {
  target = aws_db_instance.main
  values = {
    address  = "blaksmith.cluster.internal"
    port     = 5432
    db_name  = "blaksmith"
    username = "blaksmith"
    master_user_secret = [{
      secret_arn    = "arn:aws:secretsmanager:ap-southeast-2:111122223333:secret:rds!db-test"
      kms_key_id    = "arn:aws:kms:ap-southeast-2:111122223333:key/test"
      secret_status = "active"
    }]
  }
}

override_resource {
  target = aws_secretsmanager_secret.application
  values = {
    arn = "arn:aws:secretsmanager:ap-southeast-2:111122223333:secret:blaksmith-dev/application"
  }
}

override_resource {
  target = aws_ecs_task_definition.app
  values = { arn = "arn:aws:ecs:ap-southeast-2:111122223333:task-definition/blaksmith-dev:1" }
}

override_resource {
  target = aws_ecs_task_definition.api
  values = { arn = "arn:aws:ecs:ap-southeast-2:111122223333:task-definition/blaksmith-dev-api:1" }
}

override_resource {
  target = aws_ecs_task_definition.worker
  values = { arn = "arn:aws:ecs:ap-southeast-2:111122223333:task-definition/blaksmith-dev-worker:1" }
}

override_resource {
  target = aws_ecs_task_definition.migrate
  values = { arn = "arn:aws:ecs:ap-southeast-2:111122223333:task-definition/blaksmith-dev-migrate:1" }
}

variables {
  web_image_uri         = "111122223333.dkr.ecr.ap-southeast-2.amazonaws.com/blaksmith-web:test"
  api_image_uri         = "111122223333.dkr.ecr.ap-southeast-2.amazonaws.com/blaksmith-api:test"
  migrate_image_uri     = "111122223333.dkr.ecr.ap-southeast-2.amazonaws.com/blaksmith-migrate:test"
  worker_image_uri      = "111122223333.dkr.ecr.ap-southeast-2.amazonaws.com/blaksmith-worker:test"
  worker_desired_count  = 1
  public_url            = "https://blaksmith.example.gov.au"
  certificate_arn       = "arn:aws:acm:ap-southeast-2:111122223333:certificate/test"
  bootstrap_owner_email = "owner@example.gov.au"
}

run "long_running_tasks_have_required_env_and_no_bootstrap_secrets" {
  command = apply

  # Required in web, API and worker. Owner credentials are the user + rotating secret ARN.
  assert {
    condition = alltrue(flatten([
      for container in [
        jsondecode(aws_ecs_task_definition.app[0].container_definitions)[0],
        jsondecode(aws_ecs_task_definition.api[0].container_definitions)[0],
        jsondecode(aws_ecs_task_definition.worker[0].container_definitions)[0],
        ] : [
        for required in [
          "NODE_ENV", "AWS_REGION", "APP_URL", "BETTER_AUTH_URL",
          "BLAKSMITH_DB_HOST", "BLAKSMITH_DB_PORT", "BLAKSMITH_DB_NAME",
          "BLAKSMITH_DB_OWNER_USER", "BLAKSMITH_DB_OWNER_SECRET_ARN", "BLAKSMITH_DB_APP_USER",
          "DB_POOL_MAX", "BLAKSMITH_KEY_PROVIDER", "BLAKSMITH_KMS_ALIAS_PREFIX",
          "BLAKSMITH_STORAGE", "BLAKSMITH_S3_BUCKET", "BLAKSMITH_EVIDENCE_BUCKET",
        ] : contains([for e in container.environment : e.name], required)
      ]
    ]))
    error_message = "web, api and worker must each set every required environment variable."
  }

  assert {
    condition = alltrue(flatten([
      for container in [
        jsondecode(aws_ecs_task_definition.app[0].container_definitions)[0],
        jsondecode(aws_ecs_task_definition.api[0].container_definitions)[0],
        jsondecode(aws_ecs_task_definition.worker[0].container_definitions)[0],
        ] : [
        for required in ["BLAKSMITH_DB_APP_PASSWORD", "BETTER_AUTH_SECRET"] :
        contains([for s in container.secrets : s.name], required)
      ]
    ]))
    error_message = "web, api and worker must each inject the app-role password and Better Auth secret."
  }

  # #155: no owner password and no bootstrap value in any long-running task.
  assert {
    condition = alltrue(flatten([
      for container in [
        jsondecode(aws_ecs_task_definition.app[0].container_definitions)[0],
        jsondecode(aws_ecs_task_definition.api[0].container_definitions)[0],
        jsondecode(aws_ecs_task_definition.worker[0].container_definitions)[0],
        ] : [
        for name in concat(
          [for e in container.environment : e.name],
          [for s in container.secrets : s.name],
        ) : name != "BLAKSMITH_DB_OWNER_PASSWORD" && !startswith(name, "BLAKSMITH_BOOTSTRAP_")
      ]
    ]))
    error_message = "long-running tasks must not carry the owner password or any BLAKSMITH_BOOTSTRAP_* value."
  }

  # #178: the worker rejects AUTOINGEST_JOBS="[]"; the task must not set it.
  assert {
    condition = !contains(
      [for e in jsondecode(aws_ecs_task_definition.worker[0].container_definitions)[0].environment : e.name],
      "AUTOINGEST_JOBS",
    )
    error_message = "the worker task must not set AUTOINGEST_JOBS."
  }

  assert {
    condition     = contains([for e in jsondecode(aws_ecs_task_definition.api[0].container_definitions)[0].environment : e.name], "API_PORT")
    error_message = "the API task must set API_PORT."
  }

  # Owner secret ARN in the env is the RDS-managed (rotating) one.
  assert {
    condition = one([
      for e in jsondecode(aws_ecs_task_definition.app[0].container_definitions)[0].environment :
      e.value if e.name == "BLAKSMITH_DB_OWNER_SECRET_ARN"
    ]) == aws_db_instance.main.master_user_secret[0].secret_arn
    error_message = "BLAKSMITH_DB_OWNER_SECRET_ARN must be the RDS-managed master secret."
  }
}

run "migrate_is_one_shot_and_holds_the_bootstrap_secrets" {
  command = apply

  assert {
    condition     = length(aws_ecs_task_definition.migrate) == 1
    error_message = "migrate must have a task definition."
  }

  assert {
    condition = alltrue([
      for required in ["BLAKSMITH_DB_OWNER_USER", "BLAKSMITH_DB_OWNER_PASSWORD", "BLAKSMITH_DB_APP_PASSWORD", "BLAKSMITH_BOOTSTRAP_OWNER_PASSWORD"] :
      contains([for s in jsondecode(aws_ecs_task_definition.migrate[0].container_definitions)[0].secrets : s.name], required)
    ])
    error_message = "migrate must inject owner, app-role and bootstrap secrets."
  }

  # No ECS service runs the migrate family.
  assert {
    condition = alltrue([
      for svc in [aws_ecs_service.app[0], aws_ecs_service.api[0], aws_ecs_service.worker[0]] :
      svc.task_definition != aws_ecs_task_definition.migrate[0].arn
    ])
    error_message = "migrate must not run as an ECS service."
  }

  assert {
    condition = (
      aws_ecs_service.app[0].task_definition == aws_ecs_task_definition.app[0].arn &&
      aws_ecs_service.api[0].task_definition == aws_ecs_task_definition.api[0].arn &&
      aws_ecs_service.worker[0].task_definition == aws_ecs_task_definition.worker[0].arn
    )
    error_message = "web, api and worker must each run as an ECS service."
  }
}

run "database_admits_only_the_application_tier" {
  command = apply

  assert {
    condition = (
      aws_vpc_security_group_ingress_rule.database_from_service[0].security_group_id == aws_security_group.database.id &&
      aws_vpc_security_group_ingress_rule.database_from_service[0].referenced_security_group_id == aws_security_group.service[0].id &&
      aws_vpc_security_group_ingress_rule.database_from_service[0].from_port == 5432 &&
      aws_vpc_security_group_ingress_rule.database_from_service[0].to_port == 5432
    )
    error_message = "Postgres must accept 5432 from the application security group."
  }
}

run "task_role_cannot_read_the_application_secret" {
  command = apply

  # The app-role password, Better Auth secret and bootstrap password are injected by the
  # execution role. Application code reads only the rotating RDS owner secret.
  assert {
    condition = alltrue(flatten([
      for st in data.aws_iam_policy_document.task.statement : [
        for r in coalesce(st.resources, []) : r != aws_secretsmanager_secret.application.arn
      ]
    ]))
    error_message = "the task role must not be able to read the application secret."
  }

  assert {
    condition = anytrue([
      for st in data.aws_iam_policy_document.task.statement :
      contains(coalesce(st.actions, []), "secretsmanager:GetSecretValue") &&
      contains(coalesce(st.resources, []), aws_db_instance.main.master_user_secret[0].secret_arn)
    ])
    error_message = "the task role must be able to read the rotating RDS owner secret."
  }
}

run "infrastructure_only_without_images" {
  command = apply

  variables {
    web_image_uri        = ""
    api_image_uri        = ""
    migrate_image_uri    = ""
    worker_image_uri     = ""
    worker_desired_count = 0
  }

  assert {
    condition = (
      length(aws_ecs_task_definition.app) == 0 &&
      length(aws_ecs_task_definition.api) == 0 &&
      length(aws_ecs_task_definition.migrate) == 0 &&
      length(aws_ecs_task_definition.worker) == 0
    )
    error_message = "no task definitions without a web image."
  }
}

run "web_without_api_or_migrate_is_refused" {
  command = plan

  variables {
    api_image_uri     = ""
    migrate_image_uri = ""
  }

  expect_failures = [terraform_data.require_tls]
}

run "hardening_invariants" {
  command = apply

  # Every task running with readonlyRootFilesystem mounts a writable /tmp volume.
  assert {
    condition = alltrue([
      for container in [
        jsondecode(aws_ecs_task_definition.app[0].container_definitions)[0],
        jsondecode(aws_ecs_task_definition.api[0].container_definitions)[0],
        jsondecode(aws_ecs_task_definition.worker[0].container_definitions)[0],
        jsondecode(aws_ecs_task_definition.migrate[0].container_definitions)[0],
      ] : anytrue([for m in container.mountPoints : m.containerPath == "/tmp" && !m.readOnly])
    ])
    error_message = "every readonlyRootFilesystem container must mount a writable /tmp volume."
  }

  # Break-glass enforces MFA freshness via numeric aws:MultiFactorAuthAge, never ISO-8601 TokenIssueTime.
  assert {
    condition = anytrue(flatten([
      for st in data.aws_iam_policy_document.break_glass_assume.statement : [
        for c in coalesce(st.condition, []) :
        c.test == "NumericLessThanEquals" && c.variable == "aws:MultiFactorAuthAge"
      ]
    ]))
    error_message = "break-glass assume policy must use numeric aws:MultiFactorAuthAge."
  }

  # Worker circuit breaker rolls back failed deployments.
  assert {
    condition     = aws_ecs_service.worker[0].deployment_circuit_breaker[0].rollback == true
    error_message = "worker ECS service must enable deployment circuit breaker rollback."
  }

  # Non-prod environments do not create prod-only Multi-AZ/deletion-protection Config rules.
  assert {
    condition     = !contains(keys(aws_config_config_rule.managed), "rds-multi-az")
    error_message = "non-prod stacks must not attach prod-only rds-multi-az Config rule."
  }
}

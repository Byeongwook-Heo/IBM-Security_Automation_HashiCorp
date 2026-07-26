locals {
  name = "${var.name_prefix}-security-platform"
  common_tags = merge(var.tags, {
    application = "security-portal"
    component   = "backup"
    managed_by  = "terraform"
  })
}

resource "terraform_data" "guardrails" {
  count = var.enabled ? 1 : 0

  input = {
    selection = "${var.selection_tag_key}=${var.selection_tag_value}"
  }

  lifecycle {
    precondition {
      condition     = var.cost_acknowledgement == "I_ACKNOWLEDGE_SECURITY_PLATFORM_BACKUP_COSTS"
      error_message = "Set the exact backup cost acknowledgement before enabling this module."
    }

    precondition {
      condition     = var.completion_window_minutes > var.start_window_minutes
      error_message = "completion_window_minutes must be greater than start_window_minutes."
    }

    precondition {
      condition     = var.vault_lock_min_retention_days >= 7 && var.vault_lock_max_retention_days >= var.retention_days
      error_message = "Vault lock retention must cover the configured recovery-point retention."
    }

    precondition {
      condition     = !var.enable_continuous_backup || var.retention_days <= 35
      error_message = "Continuous AWS Backup recovery points support at most 35 days of retention."
    }
  }
}

resource "aws_kms_key" "backup" {
  count = var.enabled ? 1 : 0

  description             = "Security platform AWS Backup recovery points"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = merge(local.common_tags, { Name = "${local.name}-backup" })

  depends_on = [terraform_data.guardrails]

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "backup" {
  count = var.enabled ? 1 : 0

  name          = "alias/${local.name}-backup"
  target_key_id = aws_kms_key.backup[0].key_id
}

resource "aws_backup_vault" "platform" {
  count = var.enabled ? 1 : 0

  name        = "${local.name}-vault"
  kms_key_arn = aws_kms_key.backup[0].arn
  tags        = local.common_tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_backup_vault_lock_configuration" "platform" {
  count = var.enabled && var.enable_vault_lock ? 1 : 0

  backup_vault_name  = aws_backup_vault.platform[0].name
  min_retention_days = var.vault_lock_min_retention_days
  max_retention_days = var.vault_lock_max_retention_days

  # Omitting changeable_for_days keeps this in governance mode and avoids an
  # irreversible compliance-mode transition during a lab deployment.
}

data "aws_iam_policy_document" "backup_assume" {
  count = var.enabled ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "backup" {
  count = var.enabled && var.existing_backup_role_arn == null ? 1 : 0

  name                 = "${local.name}-backup-role"
  assume_role_policy   = data.aws_iam_policy_document.backup_assume[0].json
  permissions_boundary = var.permissions_boundary_arn
  tags                 = local.common_tags
}

resource "aws_iam_role_policy_attachment" "backup" {
  count = var.enabled && var.existing_backup_role_arn == null ? 1 : 0

  role       = aws_iam_role.backup[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_iam_role_policy_attachment" "restore" {
  count = var.enabled && var.existing_backup_role_arn == null ? 1 : 0

  role       = aws_iam_role.backup[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}

resource "aws_backup_plan" "platform" {
  count = var.enabled ? 1 : 0

  name = "${local.name}-daily"

  rule {
    rule_name                = "daily-retained"
    target_vault_name        = aws_backup_vault.platform[0].name
    schedule                 = var.daily_schedule
    start_window             = var.start_window_minutes
    completion_window        = var.completion_window_minutes
    enable_continuous_backup = var.enable_continuous_backup

    lifecycle {
      delete_after = var.retention_days
    }

    recovery_point_tags = merge(local.common_tags, {
      backup_frequency = "daily"
    })
  }

  tags = local.common_tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_backup_selection" "platform" {
  count = var.enabled ? 1 : 0

  iam_role_arn = var.existing_backup_role_arn != null ? trimspace(var.existing_backup_role_arn) : aws_iam_role.backup[0].arn
  name         = "${local.name}-tag-selection"
  plan_id      = aws_backup_plan.platform[0].id

  selection_tag {
    type  = "STRINGEQUALS"
    key   = var.selection_tag_key
    value = var.selection_tag_value
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_iam_role_policy_attachment.backup,
    aws_iam_role_policy_attachment.restore,
  ]
}

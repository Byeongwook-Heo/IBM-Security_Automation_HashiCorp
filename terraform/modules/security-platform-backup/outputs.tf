output "backup_vault_name" {
  value = try(aws_backup_vault.platform[0].name, null)
}

output "backup_plan_id" {
  value = try(aws_backup_plan.platform[0].id, null)
}

output "backup_role_arn" {
  value = var.existing_backup_role_arn != null ? trimspace(var.existing_backup_role_arn) : try(aws_iam_role.backup[0].arn, null)
}

output "kms_key_arn" {
  value = try(aws_kms_key.backup[0].arn, null)
}

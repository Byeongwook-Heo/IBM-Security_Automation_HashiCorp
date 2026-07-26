output "ecr_repository_url" {
  value = try(aws_ecr_repository.scanner[0].repository_url, null)
}

output "irsa_role_arn" {
  value = try(aws_iam_role.scanner[0].arn, null)
}

output "oidc_provider_arn" {
  value = local.create ? local.oidc_arn : null
}

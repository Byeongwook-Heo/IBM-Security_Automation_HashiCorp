variable "enabled" {
  type    = bool
  default = false
}

variable "name_prefix" {
  type    = string
  default = "ibm-hc-lab"
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "cluster_name" {
  type     = string
  default  = null
  nullable = true
}

variable "namespace" {
  type    = string
  default = "security-lab"
}

variable "service_account_name" {
  type    = string
  default = "vault-radar-continuous-scan"
}

variable "oidc_provider_arn" {
  description = "Existing IAM OIDC provider ARN for the selected cluster. Leave null to create it."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.oidc_provider_arn == null || can(regex(
      "^arn:aws[a-z-]*:iam::[0-9]{12}:oidc-provider/oidc\\.eks\\.[a-z0-9-]+\\.amazonaws\\.com/id/[A-Z0-9]+$",
      var.oidc_provider_arn,
    ))
    error_message = "oidc_provider_arn must be null or a valid EKS IAM OIDC provider ARN."
  }
}

variable "s3_bucket_arns" {
  description = "Exact S3 bucket ARNs Vault Radar may scan."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.s3_bucket_arns :
      can(regex("^arn:aws[a-z-]*:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", arn)) &&
      !strcontains(arn, "*")
    ])
    error_message = "s3_bucket_arns must contain exact S3 bucket ARNs without wildcards."
  }
}

variable "permissions_boundary_arn" {
  type     = string
  default  = null
  nullable = true
}

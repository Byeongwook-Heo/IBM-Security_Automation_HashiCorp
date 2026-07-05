variable "name_prefix" { type = string }
variable "tags" { type = map(string) default = {} }
variable "enabled" { type = bool default = true }

variable "enterprise_image_uri" {
  description = "Enterprise image, AMI, Helm chart, or marketplace artifact URI."
  type        = string
  default     = null
}

variable "enterprise_license_secret_arn" {
  description = "AWS Secrets Manager ARN containing enterprise license material."
  type        = string
  sensitive   = true
  default     = null
}

variable "enterprise_license_vault_path" {
  description = "Vault path containing enterprise license material for runtime injection."
  type        = string
  default     = null
}

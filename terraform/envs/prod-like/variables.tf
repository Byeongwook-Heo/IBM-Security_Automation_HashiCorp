variable "aws_region" { type = string default = "us-east-1" }
variable "name_prefix" { type = string default = "ibm-hc-lab" }
variable "enable_modules" { type = bool default = true }
variable "tags" { type = map(string) default = { owner="security-lab", application="security-portal", environment="lab", data_classification="internal", cost_center="lab", managed_by="terraform" } }
variable "qradar_api_token" { type = string sensitive = true default = null }

variable "enterprise_image_uris" {
  description = "Enterprise image/AMI/chart URIs keyed by product. Values must come from approved vendor or marketplace entitlement channels."
  type        = map(string)
  default     = {}
}

variable "enterprise_license_secret_arns" {
  description = "AWS Secrets Manager ARNs containing enterprise license material. Never place license values in Terraform code or tfvars committed to git."
  type        = map(string)
  sensitive   = true
  default     = {}
}

variable "enterprise_license_vault_paths" {
  description = "Vault KV paths containing enterprise license material for Nomad/Kubernetes runtime injection."
  type        = map(string)
  default     = {}
}

variable "name_prefix" {
  type = string
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "region" {
  type = string
}

variable "vpc_id" {
  type    = string
  default = null
}

variable "subnet_id" {
  type    = string
  default = null
}

variable "ami_name" {
  description = "Approved base AMI name. Must use hc-security-base-* or hc-base-* images."
  type        = string

  validation {
    condition     = startswith(var.ami_name, "hc-security-base-") || startswith(var.ami_name, "hc-base-")
    error_message = "ami_name must start with hc-security-base- or hc-base-."
  }
}

variable "ami_owner_ids" {
  type = list(string)
}

variable "instance_type" {
  type = string
}

variable "key_name" {
  type = string
}

variable "ssh_ingress_cidrs" {
  type = list(string)
}

variable "vault_version" {
  type = string
}

variable "vault_license_secret_arn" {
  type      = string
  sensitive = true
}

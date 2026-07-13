variable "enabled" {
  type    = bool
  default = true
}

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

variable "vpc_cidr" {
  type    = string
  default = "10.80.0.0/16"
}

variable "alb_allowed_cidr_blocks" {
  description = "Explicit restricted CIDR blocks allowed to reach the public Terraform Enterprise ALB."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.alb_allowed_cidr_blocks :
      can(cidrhost(cidr, 0)) && trimspace(cidr) != "0.0.0.0/0" && trimspace(cidr) != "::/0"
    ])
    error_message = "alb_allowed_cidr_blocks must contain valid restricted CIDRs; world-open CIDRs are forbidden."
  }
}

variable "ami_name" {
  description = "Approved base AMI name. Must use hc-security-base-* or hc-base-* images."
  type        = string
  default     = "hc-security-base-ubuntu-2204-20260629151937"

  validation {
    condition     = startswith(var.ami_name, "hc-security-base-") || startswith(var.ami_name, "hc-base-")
    error_message = "ami_name must start with hc-security-base- or hc-base-."
  }
}

variable "ami_owner_ids" {
  type    = list(string)
  default = ["888995627335"]
}

variable "instance_type" {
  type    = string
  default = "t3.xlarge"
}

variable "tfe_image_tag" {
  type    = string
  default = "v202507-1"
}

variable "license_secret_arn" {
  type        = string
  description = "AWS Secrets Manager ARN containing the raw Terraform Enterprise license."
}

variable "encryption_password_secret_arn" {
  type        = string
  description = "AWS Secrets Manager ARN containing TFE_ENCRYPTION_PASSWORD."
}

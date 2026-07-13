variable "aws_region" {
  type    = string
  default = "ap-northeast-2"
}

variable "name_prefix" {
  type    = string
  default = "ibm-hc-lab"
}

variable "tags" {
  type = map(string)
  default = {
    owner               = "security-lab"
    application         = "vault-cross-namespace-ssh-ca-test"
    environment         = "lab"
    data_classification = "internal"
    cost_center         = "lab"
    managed_by          = "terraform"
  }
}

variable "vault_license_secret_arn" {
  description = "AWS Secrets Manager ARN containing the Vault Enterprise license."
  type        = string
  sensitive   = true
}

variable "key_name" {
  description = "Existing EC2 key pair name used to SSH into the test instance."
  type        = string
}

variable "ssh_ingress_cidrs" {
  description = "CIDR blocks allowed to SSH into the test instance."
  type        = list(string)
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
  description = "Approved hc-base/hc-security-base AMI name or wildcard."
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
  default = "t3.large"
}

variable "vault_version" {
  type    = string
  default = "2.0.3+ent"
}

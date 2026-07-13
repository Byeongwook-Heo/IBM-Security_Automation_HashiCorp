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

variable "vpc_id" {
  description = "Existing VPC ID for the Elastic SIEM host. When null, the default VPC is used."
  type        = string
  default     = null
}

variable "subnet_id" {
  description = "Existing subnet ID for the Elastic SIEM host. When null, the first subnet in the selected VPC is used."
  type        = string
  default     = null
}

variable "associate_public_ip_address" {
  description = "Assign a public IP to the Elastic SIEM host. Disable this when deploying into a private subnet with an ALB or VPN path."
  type        = bool
  default     = true
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

variable "ami_architecture" {
  type    = string
  default = "x86_64"
}

variable "instance_type" {
  type    = string
  default = "t3.xlarge"
}

variable "root_volume_size" {
  description = "Root EBS volume size in GiB."
  type        = number
  default     = 200
}

variable "key_name" {
  description = "Optional EC2 key pair name for break-glass SSH access. SSM Session Manager is enabled either way."
  type        = string
  default     = null
}

variable "admin_cidr_blocks" {
  description = "CIDR blocks allowed to reach Kibana and optional admin ports. Leave empty to require SSM/VPN/private access."
  type        = list(string)
  default     = []
}

variable "enable_ssh_access" {
  type    = bool
  default = false
}

variable "enable_elasticsearch_api_access" {
  description = "Expose Elasticsearch HTTP API to admin_cidr_blocks. Keep false unless a trusted client needs direct API access."
  type        = bool
  default     = false
}

variable "elasticsearch_allowed_security_group_ids" {
  description = "Security groups allowed to reach the Elasticsearch API over the VPC when API access is enabled."
  type        = list(string)
  default     = []
}

variable "enable_fleet_server_access" {
  description = "Expose Fleet Server port 8220 to admin_cidr_blocks. The base bootstrap does not configure Fleet Server automatically."
  type        = bool
  default     = false
}

variable "enable_security_portal_access" {
  description = "Expose the co-located security portal port to admin_cidr_blocks."
  type        = bool
  default     = false
}

variable "elastic_stack_version" {
  description = "Elastic Stack Docker image tag."
  type        = string
  default     = "8.17.0"
}

variable "elastic_heap_size" {
  description = "Elasticsearch JVM heap size."
  type        = string
  default     = "4g"
}

variable "kibana_port" {
  type    = number
  default = 5601
}

variable "elasticsearch_port" {
  type    = number
  default = 9200
}

variable "fleet_server_port" {
  type    = number
  default = 8220
}

variable "security_portal_port" {
  type    = number
  default = 8080
}

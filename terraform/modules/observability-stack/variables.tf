variable "enabled" {
  description = "Create the observability host resources."
  type        = bool
  default     = true
}

variable "name_prefix" {
  description = "Prefix used for named resources."
  type        = string
}

variable "tags" {
  description = "Tags applied to resources created by this module."
  type        = map(string)
  default     = {}
}

variable "vpc_id" {
  description = "Existing VPC ID for the observability host security group."
  type        = string
  default     = null
}

variable "subnet_id" {
  description = "Existing subnet ID for the observability host."
  type        = string
  default     = null
}

variable "security_group_ids" {
  description = "Existing security group IDs to attach to the host in addition to the module-managed admin access group."
  type        = list(string)
  default     = []
}

variable "create_security_group" {
  description = "Create a security group for optional admin access to observability ports."
  type        = bool
  default     = true
}

variable "admin_cidr_blocks" {
  description = "CIDR blocks allowed to reach optional admin-facing observability ports. Leave empty to require SSM, VPN, or attached security groups."
  type        = list(string)
  default     = []
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
  description = "AWS account IDs allowed to own the selected base AMI."
  type        = list(string)
  default     = ["888995627335"]
}

variable "ami_architecture" {
  description = "AMI architecture filter."
  type        = string
  default     = "x86_64"
}

variable "instance_type" {
  description = "EC2 instance type for the observability host."
  type        = string
  default     = "t3.large"
}

variable "associate_public_ip_address" {
  description = "Assign a public IP to the host. Prefer false for private subnets with SSM, VPN, or an internal load balancer."
  type        = bool
  default     = false
}

variable "root_volume_size" {
  description = "Encrypted gp3 root EBS volume size in GiB."
  type        = number
  default     = 100
}

variable "key_name" {
  description = "Optional EC2 key pair name for break-glass SSH access. SSM Session Manager is enabled either way."
  type        = string
  default     = null
}

variable "iam_instance_profile_name" {
  description = "Optional existing IAM instance profile name. Use this when the operator cannot create IAM resources."
  type        = string
  default     = null
}

variable "create_iam_instance_profile" {
  description = "Create a minimal SSM-enabled IAM role and instance profile. Keep false when IAM creation is not permitted."
  type        = bool
  default     = false
}

variable "enable_ssh_access" {
  description = "Expose SSH from admin_cidr_blocks on the module-managed security group."
  type        = bool
  default     = false
}

variable "enable_prometheus_access" {
  description = "Expose Prometheus from admin_cidr_blocks on the module-managed security group."
  type        = bool
  default     = false
}

variable "enable_grafana_access" {
  description = "Expose Grafana from admin_cidr_blocks on the module-managed security group."
  type        = bool
  default     = true
}

variable "enable_loki_access" {
  description = "Expose Loki from admin_cidr_blocks on the module-managed security group."
  type        = bool
  default     = false
}

variable "enable_tempo_access" {
  description = "Expose Tempo from admin_cidr_blocks on the module-managed security group."
  type        = bool
  default     = false
}

variable "enable_otel_grpc_access" {
  description = "Expose OpenTelemetry OTLP gRPC from admin_cidr_blocks on the module-managed security group."
  type        = bool
  default     = false
}

variable "enable_otel_http_access" {
  description = "Expose OpenTelemetry OTLP HTTP from admin_cidr_blocks on the module-managed security group."
  type        = bool
  default     = false
}

variable "prometheus_port" {
  description = "Prometheus HTTP port."
  type        = number
  default     = 9090
}

variable "grafana_port" {
  description = "Grafana HTTP port."
  type        = number
  default     = 3000
}

variable "loki_port" {
  description = "Loki HTTP port."
  type        = number
  default     = 3100
}

variable "tempo_port" {
  description = "Tempo HTTP port."
  type        = number
  default     = 3200
}

variable "otel_grpc_port" {
  description = "OpenTelemetry OTLP gRPC port."
  type        = number
  default     = 4317
}

variable "otel_http_port" {
  description = "OpenTelemetry OTLP HTTP port."
  type        = number
  default     = 4318
}

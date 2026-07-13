variable "name_prefix" { type = string }
variable "tags" {
  type    = map(string)
  default = {}
}
variable "enabled" {
  type    = bool
  default = true
}

variable "create_test_cluster" {
  description = "Create one AWS EKS test cluster. This creates AWS resources, not a local Kubernetes cluster."
  type        = bool
  default     = false
}

variable "existing_cluster_name" {
  description = "Name of an existing EKS cluster to reference when create_test_cluster is false."
  type        = string
  default     = null
}

variable "test_cluster_name" {
  description = "Optional name for the AWS EKS test cluster created when create_test_cluster is true."
  type        = string
  default     = null
}

variable "cluster_role_arn" {
  description = "Existing IAM role ARN for the EKS control plane. Required when create_test_cluster is true."
  type        = string
  default     = null
}

variable "cluster_version" {
  description = "Optional EKS Kubernetes version. Null lets AWS select the default supported version."
  type        = string
  default     = null
}

variable "vpc_id" {
  description = "VPC ID for the EKS test cluster. Null uses the default VPC."
  type        = string
  default     = null
}

variable "subnet_ids" {
  description = "Subnet IDs for the EKS test cluster. Empty uses all subnets in the selected/default VPC."
  type        = list(string)
  default     = []
}

variable "create_cluster_security_group" {
  description = "Create a minimal EKS control-plane security group."
  type        = bool
  default     = true
}

variable "cluster_security_group_ids" {
  description = "Existing security groups to attach to the EKS control plane."
  type        = list(string)
  default     = []
}

variable "cluster_endpoint_public_access" {
  description = "Enable public EKS API endpoint access."
  type        = bool
  default     = true
}

variable "cluster_endpoint_private_access" {
  description = "Enable private EKS API endpoint access."
  type        = bool
  default     = false
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "Explicit restricted CIDR blocks allowed to reach the public EKS API endpoint. Empty is rejected when public access is enabled."
  type        = list(string)
  default     = []
}

variable "enabled_cluster_log_types" {
  description = "EKS control-plane log types to enable."
  type        = list(string)
  default     = ["api", "audit", "authenticator"]
}

variable "create_fargate_profile" {
  description = "Create a Fargate profile for the security lab namespace. This avoids worker EC2 nodes and AMI policy issues."
  type        = bool
  default     = false
}

variable "create_fargate_pod_execution_role" {
  description = "Create the IAM pod execution role required by the optional Fargate profile. Leave false when an existing role ARN is supplied."
  type        = bool
  default     = false
}

variable "fargate_pod_execution_role_arn" {
  description = "Existing IAM role ARN for EKS Fargate pod execution. Optional when create_fargate_pod_execution_role is true."
  type        = string
  default     = null
}

variable "fargate_subnet_ids" {
  description = "Private subnet IDs for Fargate pods. Empty falls back to subnet_ids; callers must ensure those subnets do not route directly to an Internet Gateway."
  type        = list(string)
  default     = []
}

variable "fargate_namespaces" {
  description = "Kubernetes namespaces selected by the optional Fargate profile."
  type        = list(string)
  default     = ["security-lab", "kube-system"]
}

variable "namespace" {
  description = "Default namespace for security platform Kubernetes resources."
  type        = string
  default     = "security-lab"
}

variable "manage_cluster_resources" {
  description = "Reserved for future Kubernetes provider-managed resources. Keep false until kubeconfig and permissions are approved."
  type        = bool
  default     = false
}

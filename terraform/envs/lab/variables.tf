variable "aws_region" {
  type    = string
  default = "us-east-1"
}
variable "name_prefix" {
  type    = string
  default = "ibm-hc-lab"
}
variable "enable_modules" {
  type    = bool
  default = true
}
variable "tags" {
  type = map(string)
  default = {
    owner               = "security-lab"
    application         = "security-portal"
    environment         = "lab"
    data_classification = "internal"
    cost_center         = "lab"
    managed_by          = "terraform"
  }
}
variable "qradar_api_token" {
  type      = string
  sensitive = true
  default   = null
}

variable "enable_terraform_enterprise" {
  type    = bool
  default = false
}

variable "enable_elastic_siem" {
  type    = bool
  default = false
}

variable "elastic_siem_vpc_id" {
  description = "Existing VPC ID for Elastic SIEM. Null uses the default VPC."
  type        = string
  default     = null
}

variable "elastic_siem_subnet_id" {
  description = "Existing subnet ID for Elastic SIEM. Null uses the first subnet in the selected VPC."
  type        = string
  default     = null
}

variable "elastic_siem_associate_public_ip_address" {
  type    = bool
  default = true
}

variable "elastic_siem_ami_name" {
  type    = string
  default = "hc-security-base-ubuntu-2204-20260629151937"
}

variable "elastic_siem_ami_owner_ids" {
  type    = list(string)
  default = ["888995627335"]
}

variable "elastic_siem_ami_architecture" {
  type    = string
  default = "x86_64"
}

variable "elastic_siem_instance_type" {
  type    = string
  default = "t3.xlarge"
}

variable "elastic_siem_root_volume_size" {
  type    = number
  default = 200
}

variable "elastic_siem_key_name" {
  type    = string
  default = null
}

variable "elastic_siem_admin_cidr_blocks" {
  description = "CIDR blocks allowed to access Kibana and optional admin ports."
  type        = list(string)
  default     = []
}

variable "elastic_siem_enable_ssh_access" {
  type    = bool
  default = false
}

variable "elastic_siem_enable_elasticsearch_api_access" {
  type    = bool
  default = false
}

variable "elastic_siem_enable_fleet_server_access" {
  type    = bool
  default = false
}

variable "elastic_siem_enable_security_portal_access" {
  type    = bool
  default = false
}

variable "elastic_siem_security_portal_port" {
  type    = number
  default = 8080
}

variable "elastic_siem_stack_version" {
  type    = string
  default = "8.17.0"
}

variable "elastic_siem_heap_size" {
  type    = string
  default = "4g"
}

variable "enable_data_security_lab" {
  type    = bool
  default = false
}

variable "enable_eks_platform" {
  description = "Reference an existing EKS/Kubernetes platform or create one AWS test EKS cluster when explicitly enabled."
  type        = bool
  default     = false
}

variable "eks_create_test_cluster" {
  description = "Create one AWS EKS test cluster. This does not create a local Kubernetes cluster."
  type        = bool
  default     = false
}

variable "eks_existing_cluster_name" {
  description = "Existing EKS cluster name used for OpenCost, Argo, StackStorm, and scanner integrations."
  type        = string
  default     = null
}

variable "eks_test_cluster_name" {
  description = "Optional name for the AWS EKS test cluster."
  type        = string
  default     = null
}

variable "eks_cluster_role_arn" {
  description = "Existing IAM role ARN for the EKS control plane. Required when eks_create_test_cluster is true."
  type        = string
  default     = null
}

variable "eks_cluster_version" {
  description = "Optional EKS Kubernetes version. Null lets AWS select the default supported version."
  type        = string
  default     = null
}

variable "eks_vpc_id" {
  description = "VPC ID for the EKS test cluster. Null uses the default VPC."
  type        = string
  default     = null
}

variable "eks_subnet_ids" {
  description = "Subnet IDs for the EKS test cluster. Empty uses all subnets in the selected/default VPC."
  type        = list(string)
  default     = []
}

variable "eks_create_cluster_security_group" {
  description = "Create a minimal EKS control-plane security group."
  type        = bool
  default     = true
}

variable "eks_cluster_security_group_ids" {
  description = "Existing security groups to attach to the EKS control plane."
  type        = list(string)
  default     = []
}

variable "eks_cluster_endpoint_public_access" {
  description = "Enable public EKS API endpoint access."
  type        = bool
  default     = true
}

variable "eks_cluster_endpoint_private_access" {
  description = "Enable private EKS API endpoint access."
  type        = bool
  default     = false
}

variable "eks_cluster_endpoint_public_access_cidrs" {
  description = "Explicit restricted CIDR blocks allowed to reach the public EKS API endpoint. Empty is rejected when public access is enabled."
  type        = list(string)
  default     = []
}

variable "eks_enabled_cluster_log_types" {
  description = "EKS control-plane log types to enable."
  type        = list(string)
  default     = ["api", "audit", "authenticator"]
}

variable "eks_create_fargate_profile" {
  description = "Create a Fargate profile for the security lab namespace. This avoids worker EC2 nodes and AMI policy issues."
  type        = bool
  default     = false
}

variable "eks_create_fargate_pod_execution_role" {
  description = "Create the IAM pod execution role for the optional EKS Fargate profile."
  type        = bool
  default     = false
}

variable "eks_fargate_pod_execution_role_arn" {
  description = "Existing IAM role ARN for EKS Fargate pod execution. Optional when eks_create_fargate_pod_execution_role is true."
  type        = string
  default     = null
}

variable "eks_fargate_subnet_ids" {
  description = "Private subnet IDs used by the optional EKS Fargate profile."
  type        = list(string)
  default     = []
}

variable "eks_fargate_namespaces" {
  description = "Kubernetes namespaces selected by the optional EKS Fargate profile."
  type        = list(string)
  default     = ["security-lab", "kube-system"]
}

variable "eks_platform_namespace" {
  description = "Namespace for security platform add-ons in the existing cluster."
  type        = string
  default     = "security-lab"
}

variable "eks_manage_cluster_resources" {
  description = "Reserved for future Kubernetes provider-managed resources. Keep false until kubeconfig and RBAC are approved."
  type        = bool
  default     = false
}

variable "data_security_lab_vpc_id" {
  description = "VPC ID for the PostgreSQL data security lab. Null uses the default VPC."
  type        = string
  default     = null
}

variable "data_security_lab_subnet_ids" {
  description = "Subnets for the PostgreSQL DB subnet group. Empty uses selected VPC subnets."
  type        = list(string)
  default     = []
}

variable "data_security_lab_db_subnet_group_name" {
  description = "Existing DB subnet group name. Null creates one from selected subnets."
  type        = string
  default     = null
}

variable "data_security_lab_publicly_accessible" {
  type    = bool
  default = false
}

variable "data_security_lab_allowed_cidr_blocks" {
  description = "CIDR blocks allowed to reach PostgreSQL."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for cidr in var.data_security_lab_allowed_cidr_blocks : can(cidrhost(cidr, 0))])
    error_message = "data_security_lab_allowed_cidr_blocks must contain valid CIDR blocks."
  }
}

variable "data_security_lab_allowed_security_group_ids" {
  description = "Security groups allowed to reach PostgreSQL."
  type        = list(string)
  default     = []
}

variable "data_security_lab_instance_class" {
  type    = string
  default = "db.t4g.micro"
}

variable "data_security_lab_allocated_storage" {
  type    = number
  default = 20

  validation {
    condition     = var.data_security_lab_allocated_storage >= 20
    error_message = "data_security_lab_allocated_storage must be at least 20 GiB."
  }
}

variable "data_security_lab_max_allocated_storage" {
  type    = number
  default = 100

  validation {
    condition     = var.data_security_lab_max_allocated_storage >= 0
    error_message = "data_security_lab_max_allocated_storage must be 0 or greater."
  }
}

variable "data_security_lab_engine_version" {
  description = "RDS PostgreSQL engine version for the data security lab."
  type        = string
  default     = "16.14"
}

variable "data_security_lab_parameter_group_family" {
  description = "RDS PostgreSQL parameter group family for pgAudit settings."
  type        = string
  default     = "postgres16"

  validation {
    condition     = can(regex("^postgres[0-9]+$", var.data_security_lab_parameter_group_family))
    error_message = "data_security_lab_parameter_group_family must use an RDS PostgreSQL family such as postgres16."
  }
}

variable "data_security_lab_db_name" {
  type    = string
  default = "security_lab"

  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9_]{0,62}$", var.data_security_lab_db_name))
    error_message = "data_security_lab_db_name must start with a letter and contain only letters, numbers, and underscores."
  }
}

variable "data_security_lab_admin_username" {
  type    = string
  default = "db_admin"

  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9_]{0,62}$", var.data_security_lab_admin_username))
    error_message = "data_security_lab_admin_username must start with a letter and contain only letters, numbers, and underscores."
  }
}

variable "data_security_lab_port" {
  type    = number
  default = 5432

  validation {
    condition     = var.data_security_lab_port >= 1 && var.data_security_lab_port <= 65535
    error_message = "data_security_lab_port must be between 1 and 65535."
  }
}

variable "data_security_lab_pgaudit_log_classes" {
  type    = string
  default = "read,write,ddl,role"

  validation {
    condition     = length(trimspace(var.data_security_lab_pgaudit_log_classes)) > 0
    error_message = "data_security_lab_pgaudit_log_classes must not be empty."
  }
}

variable "terraform_enterprise_license_secret_arn" {
  description = "AWS Secrets Manager ARN containing the raw Terraform Enterprise license."
  type        = string
  default     = null
  sensitive   = true
}

variable "terraform_enterprise_encryption_password_secret_arn" {
  description = "AWS Secrets Manager ARN containing TFE_ENCRYPTION_PASSWORD."
  type        = string
  default     = null
  sensitive   = true
}

variable "terraform_enterprise_image_tag" {
  type    = string
  default = "v202507-1"
}

variable "terraform_enterprise_ami_name" {
  type    = string
  default = "hc-security-base-ubuntu-2204-20260629151937"
}

variable "terraform_enterprise_ami_owner_ids" {
  type    = list(string)
  default = ["888995627335"]
}

variable "terraform_enterprise_instance_type" {
  type    = string
  default = "t3.xlarge"
}

variable "terraform_enterprise_vpc_cidr" {
  type    = string
  default = "10.80.0.0/16"
}

variable "terraform_enterprise_alb_allowed_cidr_blocks" {
  description = "Explicit restricted CIDR blocks allowed to reach the Terraform Enterprise ALB."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.terraform_enterprise_alb_allowed_cidr_blocks :
      can(cidrhost(cidr, 0)) && trimspace(cidr) != "0.0.0.0/0" && trimspace(cidr) != "::/0"
    ])
    error_message = "terraform_enterprise_alb_allowed_cidr_blocks must contain valid restricted CIDRs."
  }
}

variable "enable_observability_stack" {
  type    = bool
  default = false
}

variable "observability_vpc_id" {
  description = "Existing VPC ID for the Prometheus/Grafana observability stack."
  type        = string
  default     = null
}

variable "observability_subnet_id" {
  description = "Existing subnet ID for the observability stack host."
  type        = string
  default     = null
}

variable "observability_security_group_ids" {
  description = "Existing security group IDs to attach to the observability stack host."
  type        = list(string)
  default     = []
}

variable "observability_create_security_group" {
  type    = bool
  default = true
}

variable "observability_admin_cidr_blocks" {
  description = "CIDR blocks allowed to access admin-facing observability ports."
  type        = list(string)
  default     = []
}

variable "observability_ami_name" {
  type    = string
  default = "hc-security-base-ubuntu-2204-20260629151937"
}

variable "observability_ami_owner_ids" {
  type    = list(string)
  default = ["888995627335"]
}

variable "observability_ami_architecture" {
  type    = string
  default = "x86_64"
}

variable "observability_instance_type" {
  type    = string
  default = "t3.large"
}

variable "observability_associate_public_ip_address" {
  type    = bool
  default = false
}

variable "observability_root_volume_size" {
  type    = number
  default = 100
}

variable "observability_key_name" {
  type    = string
  default = null
}

variable "observability_iam_instance_profile_name" {
  description = "Existing IAM instance profile name for SSM-enabled host access."
  type        = string
  default     = null
}

variable "observability_create_iam_instance_profile" {
  type    = bool
  default = false
}

variable "observability_enable_ssh_access" {
  type    = bool
  default = false
}

variable "observability_enable_prometheus_access" {
  type    = bool
  default = false
}

variable "observability_enable_grafana_access" {
  type    = bool
  default = true
}

variable "observability_enable_loki_access" {
  type    = bool
  default = false
}

variable "observability_enable_tempo_access" {
  type    = bool
  default = false
}

variable "observability_enable_otel_grpc_access" {
  type    = bool
  default = false
}

variable "observability_enable_otel_http_access" {
  type    = bool
  default = false
}

variable "enable_stackstorm_runner" {
  description = "Create the private, review-only StackStorm single-node host. No StackStorm software is installed automatically."
  type        = bool
  default     = false
}

variable "stackstorm_runner_subnet_id" {
  description = "Existing private subnet ID for the review-only StackStorm host."
  type        = string
  default     = null
  nullable    = true
}

variable "stackstorm_runner_ami_name" {
  description = "Approved hc-security-base-* or hc-base-* AMI name filter."
  type        = string
  default     = "hc-security-base-ubuntu-2204-20260629151937"
}

variable "stackstorm_runner_ami_owner_ids" {
  description = "Trusted AWS account IDs allowed to own the StackStorm runner AMI."
  type        = list(string)
  default     = ["888995627335"]
}

variable "stackstorm_runner_instance_type" {
  description = "Review host instance type; the module enforces at least 4 vCPUs and 16 GiB RAM."
  type        = string
  default     = "m6i.xlarge"
}

variable "stackstorm_runner_root_volume_size" {
  description = "Encrypted gp3 root-volume size in GiB."
  type        = number
  default     = 100
}

variable "stackstorm_runner_root_volume_kms_key_id" {
  description = "Optional customer-managed KMS key ID or ARN for the root volume."
  type        = string
  default     = null
  nullable    = true
}

variable "stackstorm_runner_iam_instance_profile_name" {
  description = "Existing SSM-enabled IAM instance profile. Use this because the current lab operator cannot create IAM roles."
  type        = string
  default     = null
  nullable    = true
}

variable "stackstorm_runner_create_iam_instance_profile" {
  description = "Create an SSM-only instance profile. Keep false when IAM creation is not permitted."
  type        = bool
  default     = false
}

variable "stackstorm_runner_iam_role_permissions_boundary_arn" {
  description = "Optional permissions boundary for a module-created SSM role."
  type        = string
  default     = null
  nullable    = true
}

variable "stackstorm_runner_review_access_cidr_blocks" {
  description = "Restricted CIDRs allowed to reach the future review HTTPS endpoint. Empty disables ingress."
  type        = list(string)
  default     = []
}

variable "stackstorm_runner_review_access_port" {
  description = "Single TCP review port exposed only to the configured restricted CIDRs."
  type        = number
  default     = 443
}

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

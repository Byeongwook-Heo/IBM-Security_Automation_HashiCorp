locals {
  module_name         = "eks-platform"
  create_test_cluster = var.enabled && var.create_test_cluster
  cluster_enabled = (
    var.enabled &&
    !var.create_test_cluster &&
    var.existing_cluster_name != null &&
    trimspace(var.existing_cluster_name) != ""
  )
  cluster_name = (
    local.create_test_cluster
    ? coalesce(var.test_cluster_name, "${var.name_prefix}-test-eks")
    : var.existing_cluster_name
  )
  fargate_enabled = local.create_test_cluster && var.create_fargate_profile
  vpc_id = (
    local.create_test_cluster
    ? (var.vpc_id != null ? var.vpc_id : data.aws_vpc.default[0].id)
    : null
  )
  subnet_ids = (
    local.create_test_cluster
    ? (length(var.subnet_ids) > 0 ? var.subnet_ids : data.aws_subnets.selected[0].ids)
    : []
  )
  fargate_subnet_ids = (
    local.fargate_enabled
    ? (length(var.fargate_subnet_ids) > 0 ? var.fargate_subnet_ids : local.subnet_ids)
    : []
  )
  create_fargate_pod_execution_role = (
    local.fargate_enabled &&
    var.create_fargate_pod_execution_role &&
    var.fargate_pod_execution_role_arn == null
  )
  fargate_pod_execution_role_arn = (
    local.create_fargate_pod_execution_role
    ? aws_iam_role.fargate_pod_execution[0].arn
    : var.fargate_pod_execution_role_arn
  )
  managed_cluster_security_group_ids = (
    local.create_test_cluster && var.create_cluster_security_group
    ? [aws_security_group.cluster[0].id]
    : []
  )
  cluster_security_group_ids = concat(local.managed_cluster_security_group_ids, var.cluster_security_group_ids)
  common_tags                = merge(var.tags, { NamePrefix = var.name_prefix, component = local.module_name })
}

data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

data "aws_eks_cluster" "existing" {
  count = local.cluster_enabled ? 1 : 0
  name  = var.existing_cluster_name
}

data "aws_eks_cluster_auth" "existing" {
  count = local.cluster_enabled ? 1 : 0
  name  = var.existing_cluster_name
}

data "aws_vpc" "default" {
  count   = local.create_test_cluster && var.vpc_id == null ? 1 : 0
  default = true
}

data "aws_subnets" "selected" {
  count = local.create_test_cluster && length(var.subnet_ids) == 0 ? 1 : 0

  filter {
    name   = "vpc-id"
    values = [local.vpc_id]
  }
}

resource "aws_security_group" "cluster" {
  count = local.create_test_cluster && var.create_cluster_security_group ? 1 : 0

  name        = "${local.cluster_name}-cluster-sg"
  description = "EKS test cluster control plane security group"
  vpc_id      = local.vpc_id

  egress {
    description = "Allow EKS control plane egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  revoke_rules_on_delete = true

  tags = merge(local.common_tags, { Name = "${local.cluster_name}-cluster-sg" })
}

resource "aws_eks_cluster" "test" { # nosemgrep: terraform.lang.security.eks-public-endpoint-enabled.eks-public-endpoint-enabled -- restricted CIDRs are enforced by the lifecycle precondition below.
  count = local.create_test_cluster ? 1 : 0

  name                      = local.cluster_name
  role_arn                  = var.cluster_role_arn
  version                   = var.cluster_version
  enabled_cluster_log_types = var.enabled_cluster_log_types

  vpc_config {
    subnet_ids              = local.subnet_ids
    security_group_ids      = local.cluster_security_group_ids
    endpoint_public_access  = var.cluster_endpoint_public_access # nosemgrep: terraform.lang.security.eks-public-endpoint-enabled.eks-public-endpoint-enabled
    endpoint_private_access = var.cluster_endpoint_private_access
    public_access_cidrs     = length(var.cluster_endpoint_public_access_cidrs) > 0 ? var.cluster_endpoint_public_access_cidrs : null
  }

  tags = merge(local.common_tags, { Name = local.cluster_name, Role = "security-lab-test-eks" })

  lifecycle {
    precondition {
      condition     = var.cluster_role_arn != null && trimspace(var.cluster_role_arn) != ""
      error_message = "cluster_role_arn is required when create_test_cluster is true. Use an existing EKS cluster IAM role when IAM creation is not permitted."
    }

    precondition {
      condition     = length(local.subnet_ids) >= 2
      error_message = "At least two subnet IDs are required to create an EKS cluster."
    }

    precondition {
      condition     = var.cluster_endpoint_public_access || var.cluster_endpoint_private_access
      error_message = "At least one cluster endpoint access mode must be enabled."
    }

    precondition {
      condition = !var.cluster_endpoint_public_access || (
        length(var.cluster_endpoint_public_access_cidrs) > 0 &&
        alltrue([
          for cidr in var.cluster_endpoint_public_access_cidrs :
          trimspace(cidr) != "0.0.0.0/0" && trimspace(cidr) != "::/0"
        ])
      )
      error_message = "Public EKS endpoint access requires explicit restricted CIDRs; world-open CIDRs are forbidden."
    }
  }
}

resource "aws_iam_role" "fargate_pod_execution" {
  count = local.create_fargate_pod_execution_role ? 1 : 0

  name = "${local.cluster_name}-fargate-pod-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "eks-fargate-pods.amazonaws.com"
      }
      Action = "sts:AssumeRole"
      Condition = {
        ArnLike = {
          "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:eks:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:fargateprofile/${local.cluster_name}/*"
        }
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })

  tags = merge(local.common_tags, { Name = "${local.cluster_name}-fargate-pod-execution" })
}

resource "aws_iam_role_policy_attachment" "fargate_pod_execution" {
  count = local.create_fargate_pod_execution_role ? 1 : 0

  role       = aws_iam_role.fargate_pod_execution[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
}

resource "aws_eks_fargate_profile" "security_lab" {
  count = local.fargate_enabled ? 1 : 0

  cluster_name           = aws_eks_cluster.test[0].name
  fargate_profile_name   = "${local.cluster_name}-security-lab"
  pod_execution_role_arn = local.fargate_pod_execution_role_arn
  subnet_ids             = local.fargate_subnet_ids

  dynamic "selector" {
    for_each = toset(var.fargate_namespaces)

    content {
      namespace = selector.value
    }
  }

  tags = merge(local.common_tags, { Name = "${local.cluster_name}-security-lab" })

  lifecycle {
    precondition {
      condition     = local.fargate_pod_execution_role_arn != null ? trimspace(local.fargate_pod_execution_role_arn) != "" : false
      error_message = "Provide fargate_pod_execution_role_arn or enable create_fargate_pod_execution_role when create_fargate_profile is true."
    }

    precondition {
      condition     = length(var.fargate_namespaces) > 0
      error_message = "fargate_namespaces must contain at least one namespace when create_fargate_profile is true."
    }

    precondition {
      condition     = length(local.fargate_subnet_ids) >= 2
      error_message = "At least two private fargate_subnet_ids are required when create_fargate_profile is true."
    }
  }

  depends_on = [aws_iam_role_policy_attachment.fargate_pod_execution]
}

# HUMAN REVIEW REQUIRED before applying Kubernetes resources. This module only
# records the cluster integration point until kubeconfig and RBAC are confirmed.
resource "null_resource" "existing_cluster_reference" {
  count = var.enabled ? 1 : 0

  triggers = {
    module                   = local.module_name
    mode                     = local.create_test_cluster ? "create_test_cluster" : "existing_cluster"
    existing_cluster_name    = var.existing_cluster_name != null ? var.existing_cluster_name : ""
    test_cluster_name        = var.test_cluster_name != null ? var.test_cluster_name : ""
    create_fargate_profile   = tostring(var.create_fargate_profile)
    namespace                = var.namespace
    manage_cluster_resources = tostring(var.manage_cluster_resources)
  }
}

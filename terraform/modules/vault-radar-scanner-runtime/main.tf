locals {
  create = var.enabled && var.cluster_name != null
  name   = "${var.name_prefix}-vault-radar-scanner"
  common_tags = merge(var.tags, {
    application = "security-portal"
    component   = "vault-radar-scanner"
    managed_by  = "terraform"
  })
  oidc_issuer          = try(data.aws_eks_cluster.selected[0].identity[0].oidc[0].issuer, "")
  oidc_host            = trimprefix(local.oidc_issuer, "https://")
  create_oidc_provider = local.create && var.oidc_provider_arn == null
  oidc_arn = var.oidc_provider_arn != null ? var.oidc_provider_arn : try(
    aws_iam_openid_connect_provider.eks[0].arn,
    "",
  )
}

data "aws_partition" "current" {
  count = local.create ? 1 : 0
}

data "aws_caller_identity" "current" {
  count = local.create ? 1 : 0
}

data "aws_eks_cluster" "selected" {
  count = local.create ? 1 : 0
  name  = var.cluster_name
}

data "tls_certificate" "eks_oidc" {
  count = local.create_oidc_provider ? 1 : 0
  url   = local.oidc_issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  count = local.create_oidc_provider ? 1 : 0

  url             = local.oidc_issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks_oidc[0].certificates[0].sha1_fingerprint]

  tags = local.common_tags
}

resource "terraform_data" "guardrails" {
  count = var.enabled ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.cluster_name != null
      error_message = "cluster_name is required when the Vault Radar scanner runtime is enabled."
    }

    precondition {
      condition     = local.oidc_issuer != ""
      error_message = "The selected EKS cluster must expose an OIDC issuer for IRSA."
    }

    precondition {
      condition = (
        var.oidc_provider_arn == null ||
        endswith(var.oidc_provider_arn, local.oidc_host)
      )
      error_message = "oidc_provider_arn must match the selected EKS cluster OIDC issuer."
    }

    precondition {
      condition     = length(var.s3_bucket_arns) > 0
      error_message = "At least one exact S3 bucket ARN is required for the scanner."
    }
  }
}

resource "aws_ecr_repository" "scanner" {
  count = local.create ? 1 : 0

  name                 = local.name
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false

  encryption_configuration {
    encryption_type = "AES256"
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = local.common_tags

  depends_on = [terraform_data.guardrails]
}

resource "aws_ecr_lifecycle_policy" "scanner" {
  count = local.create ? 1 : 0

  repository = aws_ecr_repository.scanner[0].name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep the newest ten scanner images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 10
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

data "aws_iam_policy_document" "assume" {
  count = local.create ? 1 : 0

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = ["system:serviceaccount:${var.namespace}:${var.service_account_name}"]
    }
  }
}

resource "aws_iam_role" "scanner" {
  count = local.create ? 1 : 0

  name                 = local.name
  assume_role_policy   = data.aws_iam_policy_document.assume[0].json
  permissions_boundary = var.permissions_boundary_arn
  tags                 = local.common_tags

  depends_on = [aws_iam_openid_connect_provider.eks]
}

data "aws_iam_policy_document" "scanner" {
  count = local.create ? 1 : 0

  statement {
    sid = "ReadAwsInventory"
    actions = [
      "ec2:DescribeImages",
      "ec2:DescribeInstances",
      "ec2:DescribeRegions",
      "ec2:DescribeTags",
      "eks:DescribeAddon",
      "eks:DescribeCluster",
      "eks:DescribeFargateProfile",
      "eks:DescribeNodegroup",
      "eks:ListAddons",
      "eks:ListClusters",
      "eks:ListFargateProfiles",
      "eks:ListNodegroups",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "ListApprovedScanBuckets"
    actions   = ["s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketVersions"]
    resources = var.s3_bucket_arns
  }

  statement {
    sid     = "ReadApprovedScanBucketObjects"
    actions = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = [
      for arn in var.s3_bucket_arns : "${arn}/*"
    ]
  }
}

resource "aws_iam_role_policy" "scanner" {
  count = local.create ? 1 : 0

  name   = "${local.name}-readonly"
  role   = aws_iam_role.scanner[0].id
  policy = data.aws_iam_policy_document.scanner[0].json
}

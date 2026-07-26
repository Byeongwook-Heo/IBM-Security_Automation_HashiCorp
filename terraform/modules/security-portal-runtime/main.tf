locals {
  name                  = "${var.name_prefix}-portal-runtime"
  db_identifier         = "${var.name_prefix}-portal-postgres"
  cache_identifier      = "${var.name_prefix}-portal-cache"
  required_ids_present  = var.vpc_id != null && var.portal_subnet_id != null && var.alb_security_group_id != null && var.ollama_vpc_id != null && var.ollama_security_group_id != null && var.elastic_security_group_id != null
  create_runtime        = var.enabled && local.required_ids_present
  create_postgresql     = local.create_runtime && var.provision_postgresql && length(var.db_subnet_ids) >= 2
  create_valkey         = local.create_runtime && var.provision_valkey && length(var.cache_subnet_ids) >= 2
  create_ollama_peering = local.create_runtime && length(var.portal_route_table_ids) > 0 && length(var.ollama_route_table_ids) > 0
  create_vault_connectivity = (
    local.create_runtime &&
    var.vault_vpc_cidr != null &&
    var.vault_security_group_id != null
  )
  create_keycloak_access = local.create_runtime && var.keycloak_security_group_id != null
  portal_egress_public_ip = var.create_eip ? try(
    aws_eip.portal[0].public_ip,
    null,
    ) : var.associate_public_ip_address ? try(
    aws_instance.portal[0].public_ip,
    null,
  ) : null
  cloudwatch_log_arn     = try(aws_cloudwatch_log_group.portal[0].arn, null)
  cloudwatch_log_streams = local.cloudwatch_log_arn == null ? null : "${local.cloudwatch_log_arn}:*"
  rds_master_secret_arn  = try(aws_db_instance.postgres[0].master_user_secret[0].secret_arn, null)
  rds_master_secret_arns = compact([local.rds_master_secret_arn])
  rds_master_secret_kms_key_arn = try(
    data.aws_kms_key.rds_master_secret[0].arn,
    null,
  )

  common_tags = merge(var.tags, {
    application = "security-portal"
    component   = "dedicated-runtime"
    managed_by  = "terraform"
  })

  bootstrap_config = {
    users = [
      {
        name        = "security-portal"
        system      = true
        lock_passwd = true
        shell       = "/usr/sbin/nologin"
      },
    ]
    write_files = [
      {
        path        = "/etc/tmpfiles.d/security-portal.conf"
        owner       = "root:root"
        permissions = "0644"
        content     = <<-EOT
          d /opt/security-portal 0750 security-portal security-portal -
          d /var/lib/security-portal 0750 security-portal security-portal -
          d /var/log/security-portal 0750 security-portal security-portal -
        EOT
      },
      {
        path        = "/opt/security-portal/README"
        owner       = "security-portal:security-portal"
        permissions = "0640"
        content     = <<-EOT
          This host is the dedicated Security Portal runtime.
          Deploy application artifacts through the approved SSM workflow.
          Run the portal process as the non-login security-portal user.
          Retrieve runtime secrets directly from approved AWS or Vault stores.
        EOT
      },
    ]
    runcmd = [
      ["systemd-tmpfiles", "--create", "/etc/tmpfiles.d/security-portal.conf"],
    ]
  }

  iam_policy_statements = concat(
    [
      {
        Sid    = "SsmManagedInstance"
        Effect = "Allow"
        Action = [
          "ssm:UpdateInstanceInformation",
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel",
          "ec2messages:AcknowledgeMessage",
          "ec2messages:DeleteMessage",
          "ec2messages:FailMessage",
          "ec2messages:GetEndpoint",
          "ec2messages:GetMessages",
          "ec2messages:SendReply",
        ]
        Resource = "*"
      },
      {
        Sid    = "WritePortalLogStreams"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:DescribeLogStreams",
          "logs:PutLogEvents",
        ]
        Resource = compact([
          local.cloudwatch_log_arn,
          local.cloudwatch_log_streams,
        ])
      },
      {
        Sid      = "WritePortalMetrics"
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = var.cloudwatch_metric_namespace
          }
        }
      },
    ],
    length(var.secret_arns) == 0 ? [] : [
      {
        Sid    = "ReadExplicitPortalSecrets"
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
        ]
        Resource = var.secret_arns
      },
    ],
    length(local.rds_master_secret_arns) == 0 ? [] : [
      {
        Sid    = "ReadRdsManagedMasterSecret"
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
        ]
        Resource = local.rds_master_secret_arns
      },
    ],
    length(var.secret_kms_key_arns) == 0 ? [] : [
      {
        Sid      = "DecryptExplicitPortalSecretKeys"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.secret_kms_key_arns
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${data.aws_region.current[0].name}.amazonaws.com"
          }
        }
      },
    ],
    local.rds_master_secret_kms_key_arn == null ? [] : [
      {
        Sid      = "DecryptRdsManagedMasterSecretKey"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = local.rds_master_secret_kms_key_arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${data.aws_region.current[0].name}.amazonaws.com"
          }
        }
      },
    ],
  )
}

data "aws_region" "current" {
  count = local.create_runtime ? 1 : 0
}

data "aws_caller_identity" "current" {
  count = local.create_runtime ? 1 : 0
}

data "aws_kms_key" "rds_master_secret" {
  count = local.create_postgresql && var.rds_master_secret_kms_key_id != null ? 1 : 0

  key_id = var.rds_master_secret_kms_key_id
}

data "aws_vpc" "portal" {
  count = local.create_runtime ? 1 : 0
  id    = var.vpc_id
}

data "aws_vpc" "ollama" {
  count = local.create_runtime ? 1 : 0
  id    = var.ollama_vpc_id
}

data "aws_subnet" "portal" {
  count = local.create_runtime ? 1 : 0
  id    = var.portal_subnet_id
}

data "aws_subnet" "db" {
  for_each = local.create_postgresql ? {
    for index, subnet_id in var.db_subnet_ids : tostring(index) => subnet_id
  } : {}
  id = each.value
}

data "aws_route_table" "db" {
  for_each = local.create_postgresql ? {
    for index, subnet_id in var.db_subnet_ids : tostring(index) => subnet_id
  } : {}
  subnet_id = each.value
}

data "aws_subnet" "cache" {
  for_each = local.create_valkey ? {
    for index, subnet_id in var.cache_subnet_ids : tostring(index) => subnet_id
  } : {}
  id = each.value
}

data "aws_route_table" "cache" {
  for_each = local.create_valkey ? {
    for index, subnet_id in var.cache_subnet_ids : tostring(index) => subnet_id
  } : {}
  subnet_id = each.value
}

data "aws_route_table" "portal_peer" {
  for_each       = local.create_ollama_peering ? toset(var.portal_route_table_ids) : toset([])
  route_table_id = each.value
}

data "aws_route_table" "ollama_peer" {
  for_each       = local.create_ollama_peering ? toset(var.ollama_route_table_ids) : toset([])
  route_table_id = each.value
}

data "aws_security_group" "alb" {
  count = local.create_runtime ? 1 : 0
  id    = var.alb_security_group_id
}

data "aws_security_group" "elastic" {
  count = local.create_runtime ? 1 : 0
  id    = var.elastic_security_group_id
}

data "aws_security_group" "ollama" {
  count = local.create_runtime ? 1 : 0
  id    = var.ollama_security_group_id
}

data "aws_security_group" "vault" {
  count = local.create_vault_connectivity ? 1 : 0
  id    = var.vault_security_group_id
}

data "aws_vpc" "vault" {
  count = local.create_vault_connectivity ? 1 : 0
  id    = data.aws_security_group.vault[0].vpc_id
}

data "aws_security_group" "keycloak" {
  count = local.create_keycloak_access ? 1 : 0
  id    = var.keycloak_security_group_id
}

data "aws_security_group" "service_endpoint" {
  for_each = local.create_runtime ? toset(var.service_endpoint_security_group_ids) : toset([])
  id       = each.value
}

data "aws_ec2_instance_type" "portal" {
  count         = local.create_runtime ? 1 : 0
  instance_type = var.instance_type
}

data "aws_ami" "approved_portal" {
  count       = local.create_runtime ? 1 : 0
  most_recent = true
  owners      = ["888995627335"]

  filter {
    name   = "name"
    values = [trimspace(var.ami_name)]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "image-type"
    values = ["machine"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  lifecycle {
    postcondition {
      condition = self.architecture == "x86_64" && (
        startswith(self.name, "hc-security-base-") ||
        startswith(self.name, "hc-base-")
      )
      error_message = "The selected AMI must be an approved x86_64 hc-security-base-* or hc-base-* image."
    }
  }
}

resource "terraform_data" "configuration_guardrails" {
  count = var.enabled ? 1 : 0

  input = {
    purpose = "dedicated-security-portal-runtime"
  }

  lifecycle {
    precondition {
      condition     = var.cost_acknowledgement == "I_ACKNOWLEDGE_SECURITY_PORTAL_RUNTIME_COSTS"
      error_message = "Set cost_acknowledgement exactly to I_ACKNOWLEDGE_SECURITY_PORTAL_RUNTIME_COSTS before enabling this paid runtime."
    }

    precondition {
      condition     = var.provision_postgresql
      error_message = "Set provision_postgresql=true to explicitly acknowledge the Multi-AZ RDS cost."
    }

    precondition {
      condition     = var.provision_valkey
      error_message = "Set provision_valkey=true to explicitly acknowledge the two-node Multi-AZ ElastiCache cost."
    }

    precondition {
      condition     = local.required_ids_present
      error_message = "vpc_id, portal_subnet_id, alb_security_group_id, ollama_vpc_id, ollama_security_group_id, and elastic_security_group_id are required."
    }

    precondition {
      condition = (
        length(var.service_endpoint_security_group_ids) > 0 ||
        length(var.https_egress_ipv4_cidrs) > 0 ||
        var.acknowledge_public_https_egress
      )
      error_message = "Supply private service endpoint security groups, restricted HTTPS CIDRs, or explicitly acknowledge public HTTPS egress."
    }

    precondition {
      condition     = !(var.create_eip && var.associate_public_ip_address)
      error_message = "Choose either create_eip or associate_public_ip_address, not both."
    }

    precondition {
      condition = (
        var.vault_vpc_cidr == null &&
        var.vault_security_group_id == null
        ) || (
        var.vault_vpc_cidr != null &&
        var.vault_security_group_id != null
      )
      error_message = "Set vault_vpc_cidr and vault_security_group_id together."
    }

    precondition {
      condition = (
        var.keycloak_security_group_id == null ||
        var.create_eip ||
        var.associate_public_ip_address
      )
      error_message = "Keycloak access requires create_eip or associate_public_ip_address for a stable source CIDR."
    }

    precondition {
      condition     = length(var.db_subnet_ids) >= 2
      error_message = "db_subnet_ids must contain at least two private subnets."
    }

    precondition {
      condition     = length(var.cache_subnet_ids) >= 2
      error_message = "cache_subnet_ids must contain at least two private subnets."
    }

    precondition {
      condition     = length(var.portal_route_table_ids) > 0 && length(var.ollama_route_table_ids) > 0
      error_message = "Explicit portal_route_table_ids and ollama_route_table_ids are required for direct Ollama VPC peering."
    }

    precondition {
      condition     = var.vpc_id != var.ollama_vpc_id
      error_message = "ollama_vpc_id must identify a different VPC from the portal VPC."
    }

    precondition {
      condition     = try(data.aws_vpc.portal[0].owner_id, null) == try(data.aws_caller_identity.current[0].account_id, null)
      error_message = "The portal VPC must belong to the current AWS account."
    }

    precondition {
      condition     = try(data.aws_vpc.ollama[0].owner_id, null) == try(data.aws_caller_identity.current[0].account_id, null)
      error_message = "The Ollama VPC must belong to the current AWS account."
    }

    precondition {
      condition     = try(data.aws_subnet.portal[0].vpc_id, null) == var.vpc_id
      error_message = "portal_subnet_id must belong to vpc_id."
    }

    precondition {
      condition = alltrue([
        for subnet in values(data.aws_subnet.db) : subnet.vpc_id == var.vpc_id
      ])
      error_message = "Every PostgreSQL subnet must belong to vpc_id."
    }

    precondition {
      condition = alltrue([
        for subnet in values(data.aws_subnet.cache) : subnet.vpc_id == var.vpc_id
      ])
      error_message = "Every Valkey subnet must belong to vpc_id."
    }

    precondition {
      condition = length(distinct([
        for subnet in values(data.aws_subnet.db) : subnet.availability_zone
      ])) >= 2
      error_message = "PostgreSQL subnets must span at least two Availability Zones."
    }

    precondition {
      condition = length(distinct([
        for subnet in values(data.aws_subnet.cache) : subnet.availability_zone
      ])) >= 2
      error_message = "Valkey subnets must span at least two Availability Zones."
    }

    precondition {
      condition = alltrue([
        for subnet in values(data.aws_subnet.db) : !subnet.map_public_ip_on_launch
      ])
      error_message = "PostgreSQL subnets must not auto-assign public IPv4 addresses."
    }

    precondition {
      condition = alltrue([
        for subnet in values(data.aws_subnet.cache) : !subnet.map_public_ip_on_launch
      ])
      error_message = "Valkey subnets must not auto-assign public IPv4 addresses."
    }

    precondition {
      condition = alltrue([
        for route_table in values(data.aws_route_table.db) : alltrue([
          for route in route_table.routes :
          !try(startswith(route.gateway_id, "igw-"), false)
        ])
      ])
      error_message = "PostgreSQL subnets must use private route tables without direct internet-gateway routes."
    }

    precondition {
      condition = alltrue([
        for route_table in values(data.aws_route_table.cache) : alltrue([
          for route in route_table.routes :
          !try(startswith(route.gateway_id, "igw-"), false)
        ])
      ])
      error_message = "Valkey subnets must use private route tables without direct internet-gateway routes."
    }

    precondition {
      condition = alltrue([
        for route_table in values(data.aws_route_table.portal_peer) : route_table.vpc_id == var.vpc_id
      ])
      error_message = "Every portal_route_table_id must belong to vpc_id."
    }

    precondition {
      condition = alltrue([
        for route_table in values(data.aws_route_table.ollama_peer) : route_table.vpc_id == var.ollama_vpc_id
      ])
      error_message = "Every ollama_route_table_id must belong to ollama_vpc_id."
    }

    precondition {
      condition     = try(data.aws_security_group.alb[0].vpc_id, null) == var.vpc_id
      error_message = "alb_security_group_id must belong to the portal VPC."
    }

    precondition {
      condition     = try(data.aws_security_group.elastic[0].vpc_id, null) == var.vpc_id
      error_message = "elastic_security_group_id must belong to the portal VPC so private SG references remain scoped."
    }

    precondition {
      condition     = try(data.aws_security_group.ollama[0].vpc_id, null) == var.ollama_vpc_id
      error_message = "ollama_security_group_id must belong to ollama_vpc_id."
    }

    precondition {
      condition = !local.create_vault_connectivity || (
        try(data.aws_vpc.vault[0].cidr_block, null) == var.vault_vpc_cidr &&
        try(data.aws_vpc.vault[0].id, null) != var.vpc_id
      )
      error_message = "vault_vpc_cidr must exactly match the non-portal VPC that owns vault_security_group_id."
    }

    precondition {
      condition = !local.create_keycloak_access || (
        try(data.aws_security_group.keycloak[0].vpc_id, null) != var.vpc_id
      )
      error_message = "keycloak_security_group_id must belong to the external Keycloak VPC."
    }

    precondition {
      condition = alltrue([
        for security_group in values(data.aws_security_group.service_endpoint) :
        security_group.vpc_id == var.vpc_id
      ])
      error_message = "Every service endpoint security group must belong to the portal VPC."
    }

    precondition {
      condition     = var.rds_multi_az
      error_message = "rds_multi_az must remain true for the dedicated runtime."
    }

    precondition {
      condition     = var.rds_deletion_protection
      error_message = "rds_deletion_protection must remain true for the dedicated runtime."
    }

    precondition {
      condition     = var.rds_backup_retention_days >= 7
      error_message = "RDS automated backups must be retained for at least seven days."
    }

    precondition {
      condition     = var.db_max_allocated_storage >= var.db_allocated_storage
      error_message = "db_max_allocated_storage must be greater than or equal to db_allocated_storage."
    }
  }
}

resource "aws_cloudwatch_log_group" "portal" {
  count = local.create_runtime ? 1 : 0

  name              = "/security-portal/${local.name}"
  retention_in_days = var.cloudwatch_log_retention_days
  kms_key_id        = var.cloudwatch_log_kms_key_id

  tags = merge(local.common_tags, { Name = "${local.name}-logs" })

  depends_on = [terraform_data.configuration_guardrails]
}

resource "aws_iam_role" "portal" {
  count = local.create_runtime ? 1 : 0

  name                 = "${local.name}-role"
  permissions_boundary = var.iam_permissions_boundary_arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = merge(local.common_tags, { Name = "${local.name}-role" })

  depends_on = [terraform_data.configuration_guardrails]
}

resource "aws_iam_role_policy" "portal" {
  count = local.create_runtime ? 1 : 0

  name = "${local.name}-minimum-runtime"
  role = aws_iam_role.portal[0].id

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = local.iam_policy_statements
  })
}

resource "aws_iam_instance_profile" "portal" {
  count = local.create_runtime ? 1 : 0

  name = "${local.name}-profile"
  role = aws_iam_role.portal[0].name

  tags = merge(local.common_tags, { Name = "${local.name}-profile" })
}

resource "aws_security_group" "portal" {
  count = local.create_runtime ? 1 : 0

  name_prefix            = "${local.name}-"
  description            = "Dedicated Security Portal runtime; ALB ingress only"
  vpc_id                 = var.vpc_id
  revoke_rules_on_delete = true

  tags = merge(local.common_tags, { Name = "${local.name}-sg" })

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [terraform_data.configuration_guardrails]
}

resource "aws_vpc_security_group_ingress_rule" "portal_from_alb" {
  count = local.create_runtime ? 1 : 0

  security_group_id            = aws_security_group.portal[0].id
  referenced_security_group_id = var.alb_security_group_id
  description                  = "Portal HTTP from the dedicated ALB only"
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "dns_udp" {
  count = local.create_runtime ? 1 : 0

  security_group_id = aws_security_group.portal[0].id
  description       = "DNS to the VPC resolver"
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
  cidr_ipv4         = "${cidrhost(data.aws_vpc.portal[0].cidr_block, 2)}/32"
}

resource "aws_vpc_security_group_egress_rule" "dns_tcp" {
  count = local.create_runtime ? 1 : 0

  security_group_id = aws_security_group.portal[0].id
  description       = "TCP DNS to the VPC resolver"
  from_port         = 53
  to_port           = 53
  ip_protocol       = "tcp"
  cidr_ipv4         = "${cidrhost(data.aws_vpc.portal[0].cidr_block, 2)}/32"
}

resource "aws_vpc_security_group_egress_rule" "service_endpoint_https" {
  for_each = local.create_runtime ? toset(var.service_endpoint_security_group_ids) : toset([])

  security_group_id            = aws_security_group.portal[0].id
  referenced_security_group_id = each.value
  description                  = "HTTPS to approved AWS interface endpoints"
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "service_endpoint_from_portal" {
  for_each = local.create_runtime ? toset(var.service_endpoint_security_group_ids) : toset([])

  security_group_id            = each.value
  referenced_security_group_id = aws_security_group.portal[0].id
  description                  = "HTTPS from the dedicated Security Portal"
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "restricted_https" {
  for_each = local.create_runtime ? toset(var.https_egress_ipv4_cidrs) : toset([])

  security_group_id = aws_security_group.portal[0].id
  description       = "Restricted HTTPS egress explicitly supplied by the operator"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "public_https" {
  count = local.create_runtime && var.acknowledge_public_https_egress ? 1 : 0

  security_group_id = aws_security_group.portal[0].id
  description       = "Explicitly acknowledged public HTTPS egress for the EIP-backed runtime"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_peering_connection" "ollama" {
  count = local.create_ollama_peering ? 1 : 0

  vpc_id        = var.vpc_id
  peer_vpc_id   = var.ollama_vpc_id
  peer_owner_id = data.aws_caller_identity.current[0].account_id
  auto_accept   = true

  tags = merge(local.common_tags, {
    Name    = "${local.name}-to-ollama"
    purpose = "portal-to-shared-ollama-11434"
  })

  depends_on = [terraform_data.configuration_guardrails]
}

resource "aws_vpc_peering_connection_options" "ollama" {
  count = local.create_ollama_peering ? 1 : 0

  vpc_peering_connection_id = aws_vpc_peering_connection.ollama[0].id

  requester {
    allow_remote_vpc_dns_resolution = true
  }

  accepter {
    allow_remote_vpc_dns_resolution = true
  }
}

resource "aws_route" "portal_to_ollama" {
  for_each = local.create_ollama_peering ? toset(var.portal_route_table_ids) : toset([])

  route_table_id            = each.value
  destination_cidr_block    = data.aws_vpc.ollama[0].cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection.ollama[0].id

  depends_on = [aws_vpc_peering_connection_options.ollama]
}

resource "aws_route" "ollama_to_portal" {
  for_each = local.create_ollama_peering ? toset(var.ollama_route_table_ids) : toset([])

  route_table_id            = each.value
  destination_cidr_block    = data.aws_vpc.portal[0].cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection.ollama[0].id

  depends_on = [aws_vpc_peering_connection_options.ollama]
}

resource "aws_vpc_security_group_ingress_rule" "ollama_from_portal" {
  count = local.create_ollama_peering ? 1 : 0

  security_group_id            = var.ollama_security_group_id
  referenced_security_group_id = aws_security_group.portal[0].id
  description                  = "Ollama API from the dedicated Security Portal only"
  from_port                    = 11434
  to_port                      = 11434
  ip_protocol                  = "tcp"

  depends_on = [
    aws_route.portal_to_ollama,
    aws_route.ollama_to_portal,
  ]
}

resource "aws_vpc_security_group_egress_rule" "ollama" {
  count = local.create_ollama_peering ? 1 : 0

  security_group_id            = aws_security_group.portal[0].id
  referenced_security_group_id = var.ollama_security_group_id
  description                  = "Portal requests to shared Ollama API only"
  from_port                    = 11434
  to_port                      = 11434
  ip_protocol                  = "tcp"

  depends_on = [
    aws_route.portal_to_ollama,
    aws_route.ollama_to_portal,
  ]
}

resource "aws_vpc_security_group_ingress_rule" "elastic_from_portal" {
  for_each = local.create_runtime ? toset(["5601", "9200"]) : toset([])

  security_group_id            = var.elastic_security_group_id
  referenced_security_group_id = aws_security_group.portal[0].id
  description                  = "Elastic private TCP/${each.value} from the dedicated Security Portal"
  from_port                    = tonumber(each.value)
  to_port                      = tonumber(each.value)
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "elastic" {
  for_each = local.create_runtime ? toset(["5601", "9200"]) : toset([])

  security_group_id            = aws_security_group.portal[0].id
  referenced_security_group_id = var.elastic_security_group_id
  description                  = "Portal requests to Elastic private TCP/${each.value}"
  from_port                    = tonumber(each.value)
  to_port                      = tonumber(each.value)
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "vault" {
  count = local.create_vault_connectivity ? 1 : 0

  security_group_id = aws_security_group.portal[0].id
  cidr_ipv4         = var.vault_vpc_cidr
  description       = "Portal requests to the existing private Vault NLB"
  from_port         = 8200
  to_port           = 8200
  ip_protocol       = "tcp"
}

resource "aws_instance" "portal" {
  count = local.create_runtime ? 1 : 0

  ami                         = data.aws_ami.approved_portal[0].id
  instance_type               = var.instance_type
  subnet_id                   = var.portal_subnet_id
  associate_public_ip_address = var.associate_public_ip_address
  vpc_security_group_ids      = [aws_security_group.portal[0].id]
  iam_instance_profile        = aws_iam_instance_profile.portal[0].name
  monitoring                  = true
  source_dest_check           = true

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_size
    encrypted             = true
    kms_key_id            = var.root_volume_kms_key_id
    delete_on_termination = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  user_data                   = "#cloud-config\n${yamlencode(local.bootstrap_config)}"
  user_data_replace_on_change = false

  tags = merge(local.common_tags, {
    Name         = "${local.name}-ec2"
    Role         = "security-portal"
    backup_scope = "security-portal-core"
  })

  volume_tags = merge(local.common_tags, {
    Name = "${local.name}-root"
  })

  lifecycle {
    precondition {
      condition     = contains(data.aws_ec2_instance_type.portal[0].supported_architectures, "x86_64")
      error_message = "instance_type must support the x86_64 architecture used by the approved AMI."
    }
  }

  depends_on = [
    aws_iam_role_policy.portal,
    aws_vpc_security_group_ingress_rule.portal_from_alb,
    aws_vpc_security_group_egress_rule.dns_tcp,
    aws_vpc_security_group_egress_rule.dns_udp,
    aws_vpc_security_group_egress_rule.service_endpoint_https,
    aws_vpc_security_group_ingress_rule.service_endpoint_from_portal,
    aws_vpc_security_group_egress_rule.restricted_https,
    aws_vpc_security_group_egress_rule.public_https,
  ]
}

resource "aws_vpc_security_group_ingress_rule" "vault_from_portal" {
  count = local.create_vault_connectivity ? 1 : 0

  security_group_id = var.vault_security_group_id
  cidr_ipv4         = "${aws_instance.portal[0].private_ip}/32"
  description       = "Vault read-only API from the dedicated Security Portal"
  from_port         = 8200
  to_port           = 8200
  ip_protocol       = "tcp"
}

resource "aws_eip" "portal" {
  count = local.create_runtime && var.create_eip ? 1 : 0

  domain = "vpc"

  tags = merge(local.common_tags, { Name = "${local.name}-eip" })

  depends_on = [terraform_data.configuration_guardrails]
}

resource "aws_eip_association" "portal" {
  count = local.create_runtime && var.create_eip ? 1 : 0

  allocation_id = aws_eip.portal[0].id
  instance_id   = aws_instance.portal[0].id
}

resource "aws_vpc_security_group_ingress_rule" "keycloak_from_portal" {
  count = local.create_keycloak_access ? 1 : 0

  security_group_id = var.keycloak_security_group_id
  cidr_ipv4         = "${local.portal_egress_public_ip}/32"
  description       = "Keycloak OIDC HTTPS from the dedicated Security Portal"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_security_group" "postgres" {
  count = local.create_postgresql ? 1 : 0

  name_prefix            = "${local.db_identifier}-"
  description            = "Private PostgreSQL for the dedicated Security Portal"
  vpc_id                 = var.vpc_id
  revoke_rules_on_delete = true

  tags = merge(local.common_tags, { Name = "${local.db_identifier}-sg" })

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [terraform_data.configuration_guardrails]
}

resource "aws_vpc_security_group_ingress_rule" "postgres_from_portal" {
  count = local.create_postgresql ? 1 : 0

  security_group_id            = aws_security_group.postgres[0].id
  referenced_security_group_id = aws_security_group.portal[0].id
  description                  = "PostgreSQL TLS from the dedicated Security Portal only"
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "postgres" {
  count = local.create_postgresql ? 1 : 0

  security_group_id            = aws_security_group.portal[0].id
  referenced_security_group_id = aws_security_group.postgres[0].id
  description                  = "Portal to private PostgreSQL"
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_db_subnet_group" "postgres" {
  count = local.create_postgresql ? 1 : 0

  name        = "${local.db_identifier}-subnets"
  description = "Private PostgreSQL subnets for the Security Portal"
  subnet_ids  = var.db_subnet_ids

  tags = merge(local.common_tags, { Name = "${local.db_identifier}-subnets" })
}

resource "aws_db_parameter_group" "postgres_tls" {
  count = local.create_postgresql ? 1 : 0

  name        = "${local.db_identifier}-tls"
  description = "PostgreSQL TLS and connection audit posture for the Security Portal"
  family      = "postgres16"

  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }

  parameter {
    name         = "ssl_min_protocol_version"
    value        = "TLSv1.2"
    apply_method = "pending-reboot"
  }

  parameter {
    name         = "log_connections"
    value        = "1"
    apply_method = "immediate"
  }

  parameter {
    name         = "log_disconnections"
    value        = "1"
    apply_method = "immediate"
  }

  tags = merge(local.common_tags, { Name = "${local.db_identifier}-tls" })
}

resource "aws_db_instance" "postgres" {
  count = local.create_postgresql ? 1 : 0

  identifier     = local.db_identifier
  engine         = "postgres"
  engine_version = var.db_engine_version
  instance_class = var.db_instance_class

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = var.rds_kms_key_id

  db_name  = var.db_name
  username = var.db_master_username
  port     = 5432

  manage_master_user_password   = true
  master_user_secret_kms_key_id = var.rds_master_secret_kms_key_id

  db_subnet_group_name   = aws_db_subnet_group.postgres[0].name
  vpc_security_group_ids = [aws_security_group.postgres[0].id]
  parameter_group_name   = aws_db_parameter_group.postgres_tls[0].name
  publicly_accessible    = false
  network_type           = "IPV4"

  multi_az                     = var.rds_multi_az
  backup_retention_period      = var.rds_backup_retention_days
  auto_minor_version_upgrade   = true
  deletion_protection          = var.rds_deletion_protection
  skip_final_snapshot          = false
  final_snapshot_identifier    = "${local.db_identifier}-final"
  copy_tags_to_snapshot        = true
  delete_automated_backups     = false
  performance_insights_enabled = true

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  tags = merge(local.common_tags, {
    Name         = local.db_identifier
    Role         = "security-portal-postgresql"
    backup_scope = "security-portal-core"
  })

  depends_on = [
    aws_vpc_security_group_ingress_rule.postgres_from_portal,
    terraform_data.configuration_guardrails,
  ]
}

resource "aws_security_group" "valkey" {
  count = local.create_valkey ? 1 : 0

  name_prefix            = "${local.cache_identifier}-"
  description            = "Private encrypted Valkey for Security Portal sessions"
  vpc_id                 = var.vpc_id
  revoke_rules_on_delete = true

  tags = merge(local.common_tags, { Name = "${local.cache_identifier}-sg" })

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [terraform_data.configuration_guardrails]
}

resource "aws_vpc_security_group_ingress_rule" "valkey_from_portal" {
  count = local.create_valkey ? 1 : 0

  security_group_id            = aws_security_group.valkey[0].id
  referenced_security_group_id = aws_security_group.portal[0].id
  description                  = "Valkey TLS from the dedicated Security Portal only"
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "valkey" {
  count = local.create_valkey ? 1 : 0

  security_group_id            = aws_security_group.portal[0].id
  referenced_security_group_id = aws_security_group.valkey[0].id
  description                  = "Portal to private encrypted Valkey"
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
}

resource "aws_elasticache_subnet_group" "valkey" {
  count = local.create_valkey ? 1 : 0

  name        = "${local.cache_identifier}-subnets"
  description = "Private Valkey subnets for the Security Portal"
  subnet_ids  = var.cache_subnet_ids

  tags = merge(local.common_tags, { Name = "${local.cache_identifier}-subnets" })
}

resource "aws_elasticache_replication_group" "valkey" {
  count = local.create_valkey ? 1 : 0

  replication_group_id = local.cache_identifier
  description          = "Two-node encrypted Security Portal session cache"
  engine               = var.cache_engine
  engine_version       = var.cache_engine_version
  node_type            = var.cache_node_type
  port                 = 6379

  num_cache_clusters         = 2
  automatic_failover_enabled = true
  multi_az_enabled           = true
  transit_encryption_enabled = true
  transit_encryption_mode    = "required"
  at_rest_encryption_enabled = true
  kms_key_id                 = var.cache_kms_key_id
  snapshot_retention_limit   = var.cache_snapshot_retention_days
  auto_minor_version_upgrade = true
  apply_immediately          = false

  subnet_group_name  = aws_elasticache_subnet_group.valkey[0].name
  security_group_ids = [aws_security_group.valkey[0].id]

  tags = merge(local.common_tags, {
    Name = local.cache_identifier
    Role = "security-portal-session-cache"
  })

  depends_on = [
    aws_vpc_security_group_ingress_rule.valkey_from_portal,
    terraform_data.configuration_guardrails,
  ]
}

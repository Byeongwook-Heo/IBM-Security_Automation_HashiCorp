data "aws_vpc" "default" {
  count   = var.enabled && var.vpc_id == null ? 1 : 0
  default = true
}

data "aws_subnets" "selected" {
  count = var.enabled && var.subnet_id == null ? 1 : 0

  filter {
    name   = "vpc-id"
    values = [local.vpc_id]
  }
}

data "aws_ami" "allowed_base" {
  count       = var.enabled ? 1 : 0
  most_recent = true
  owners      = var.ami_owner_ids

  filter {
    name   = "name"
    values = [var.ami_name]
  }

  filter {
    name   = "architecture"
    values = [var.ami_architecture]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  name              = "${var.name_prefix}-elastic-siem"
  vpc_id            = var.enabled ? (var.vpc_id != null ? var.vpc_id : data.aws_vpc.default[0].id) : null
  subnet_id         = var.enabled ? (var.subnet_id != null ? var.subnet_id : element(sort(data.aws_subnets.selected[0].ids), 0)) : null
  common_tags       = merge(var.tags, { NamePrefix = local.name, component = "elastic-siem" })
  credentials_name  = "${local.name}/bootstrap-credentials"
  has_admin_ingress = length(var.admin_cidr_blocks) > 0
}

resource "aws_secretsmanager_secret" "credentials" {
  count = var.enabled ? 1 : 0

  name                    = local.credentials_name
  recovery_window_in_days = 0

  tags = merge(local.common_tags, { Name = local.credentials_name })
}

resource "aws_security_group" "this" {
  count = var.enabled ? 1 : 0

  name        = "${local.name}-sg"
  description = "Elastic SIEM host access"
  vpc_id      = local.vpc_id

  dynamic "ingress" {
    for_each = local.has_admin_ingress ? [1] : []

    content {
      description = "Kibana from admin CIDRs"
      from_port   = var.kibana_port
      to_port     = var.kibana_port
      protocol    = "tcp"
      cidr_blocks = var.admin_cidr_blocks
    }
  }

  dynamic "ingress" {
    for_each = local.has_admin_ingress && var.enable_elasticsearch_api_access ? [1] : []

    content {
      description = "Elasticsearch API from admin CIDRs"
      from_port   = var.elasticsearch_port
      to_port     = var.elasticsearch_port
      protocol    = "tcp"
      cidr_blocks = var.admin_cidr_blocks
    }
  }

  dynamic "ingress" {
    for_each = toset(var.elasticsearch_allowed_security_group_ids)

    content {
      description     = "Elasticsearch API from trusted security groups"
      from_port       = var.elasticsearch_port
      to_port         = var.elasticsearch_port
      protocol        = "tcp"
      security_groups = [ingress.value]
    }
  }

  dynamic "ingress" {
    for_each = local.has_admin_ingress && var.enable_fleet_server_access ? [1] : []

    content {
      description = "Fleet Server from admin CIDRs"
      from_port   = var.fleet_server_port
      to_port     = var.fleet_server_port
      protocol    = "tcp"
      cidr_blocks = var.admin_cidr_blocks
    }
  }

  dynamic "ingress" {
    for_each = local.has_admin_ingress && var.enable_security_portal_access ? [1] : []

    content {
      description = "Security Portal from admin CIDRs"
      from_port   = var.security_portal_port
      to_port     = var.security_portal_port
      protocol    = "tcp"
      cidr_blocks = var.admin_cidr_blocks
    }
  }

  dynamic "ingress" {
    for_each = local.has_admin_ingress && var.enable_ssh_access ? [1] : []

    content {
      description = "SSH from admin CIDRs"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = var.admin_cidr_blocks
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${local.name}-sg" })
}

resource "aws_iam_role" "instance" {
  count = var.enabled ? 1 : 0

  name = "${local.name}-instance-role"

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

  tags = merge(local.common_tags, { Name = "${local.name}-instance-role" })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  count = var.enabled ? 1 : 0

  role       = aws_iam_role.instance[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "bootstrap" {
  count = var.enabled ? 1 : 0

  name = "${local.name}-bootstrap"
  role = aws_iam_role.instance[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecret"
        ]
        Resource = aws_secretsmanager_secret.credentials[0].arn
      }
    ]
  })
}

resource "aws_iam_instance_profile" "this" {
  count = var.enabled ? 1 : 0

  name = "${local.name}-instance-profile"
  role = aws_iam_role.instance[0].name

  tags = merge(local.common_tags, { Name = "${local.name}-instance-profile" })
}

resource "aws_instance" "this" {
  count = var.enabled ? 1 : 0

  ami                         = data.aws_ami.allowed_base[0].id
  instance_type               = var.instance_type
  subnet_id                   = local.subnet_id
  vpc_security_group_ids      = [aws_security_group.this[0].id]
  iam_instance_profile        = aws_iam_instance_profile.this[0].name
  associate_public_ip_address = var.associate_public_ip_address
  key_name                    = var.key_name

  root_block_device {
    volume_size = var.root_volume_size
    volume_type = "gp3"
    encrypted   = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  # Runtime updates are deployed through SSM; never replace this stateful host for a bootstrap-script change.
  user_data_replace_on_change = false
  user_data = templatefile("${path.module}/templates/user_data.sh.tftpl", {
    region                        = var.region
    elastic_stack_version         = var.elastic_stack_version
    elastic_heap_size             = var.elastic_heap_size
    credentials_secret_arn        = aws_secretsmanager_secret.credentials[0].arn
    kibana_port                   = var.kibana_port
    elasticsearch_port            = var.elasticsearch_port
    elasticsearch_bind_address    = var.enable_elasticsearch_api_access ? "0.0.0.0" : "127.0.0.1"
    elasticsearch_external_access = var.enable_elasticsearch_api_access
    fleet_server_port             = var.fleet_server_port
  })

  tags = merge(local.common_tags, {
    Name = "${local.name}-host"
    Role = "elastic-siem"
  })

  lifecycle {
    ignore_changes = [user_data]
  }

  depends_on = [
    aws_iam_role_policy_attachment.ssm,
    aws_iam_role_policy.bootstrap
  ]
}

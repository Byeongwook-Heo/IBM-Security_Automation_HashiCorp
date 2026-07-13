data "aws_caller_identity" "current" {}

data "aws_vpc" "default" {
  count   = var.vpc_id == null ? 1 : 0
  default = true
}

data "aws_subnets" "default" {
  count = var.subnet_id == null ? 1 : 0

  filter {
    name   = "vpc-id"
    values = [local.vpc_id]
  }

  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}

data "aws_ami" "approved" {
  most_recent = true
  owners      = var.ami_owner_ids

  filter {
    name   = "name"
    values = [var.ami_name]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}

locals {
  name      = "${var.name_prefix}-vault-xns-sshca"
  vpc_id    = coalesce(var.vpc_id, try(data.aws_vpc.default[0].id, null))
  subnet_id = coalesce(var.subnet_id, try(sort(data.aws_subnets.default[0].ids)[0], null))
  tags      = merge(var.tags, { component = "vault-cross-namespace-ssh-ca-test" })
}

resource "aws_security_group" "this" {
  name        = "${local.name}-sg"
  description = "Vault cross-namespace SSH CA test instance"
  vpc_id      = local.vpc_id

  ingress {
    description = "SSH from operator workstation"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ssh_ingress_cidrs
  }

  egress {
    description = "Outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.name}-sg" })
}

resource "aws_iam_role" "this" {
  name = "${local.name}-role"

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

  tags = merge(local.tags, { Name = "${local.name}-role" })
}

resource "aws_iam_role_policy" "license_read" {
  name = "${local.name}-license-read"
  role = aws_iam_role.this.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = var.vault_license_secret_arn
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "this" {
  name = "${local.name}-profile"
  role = aws_iam_role.this.name

  tags = merge(local.tags, { Name = "${local.name}-profile" })
}

resource "aws_instance" "this" {
  ami                         = data.aws_ami.approved.id
  instance_type               = var.instance_type
  subnet_id                   = local.subnet_id
  associate_public_ip_address = true
  key_name                    = var.key_name
  vpc_security_group_ids      = [aws_security_group.this.id]
  iam_instance_profile        = aws_iam_instance_profile.this.name
  user_data_replace_on_change = true

  user_data = templatefile("${path.module}/templates/user_data.sh.tftpl", {
    region                   = var.region
    vault_version            = var.vault_version
    vault_license_secret_arn = var.vault_license_secret_arn
  })

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    encrypted   = true
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = merge(local.tags, {
    Name            = "${local.name}-instance"
    ApprovedAMIName = data.aws_ami.approved.name
  })

  depends_on = [
    aws_iam_role_policy.license_read,
    aws_iam_role_policy_attachment.ssm
  ]
}

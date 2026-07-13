locals {
  name        = "${var.name_prefix}-stackstorm-runner"
  create_host = var.enabled && var.subnet_id != null

  existing_instance_profile_name = var.iam_instance_profile_name == null ? null : trimspace(var.iam_instance_profile_name)
  existing_instance_profile_set  = try(length(local.existing_instance_profile_name) > 0, false)
  should_create_instance_profile = local.create_host && var.create_iam_instance_profile
  instance_profile_name          = local.should_create_instance_profile ? try(aws_iam_instance_profile.this[0].name, null) : local.existing_instance_profile_name

  review_access_cidrs = [
    for cidr in var.review_access_cidr_blocks : trimspace(cidr)
  ]

  common_tags = merge(var.tags, {
    component  = "stackstorm-runner"
    deployment = "review-only"
  })

  review_scaffold = {
    write_files = [
      {
        path        = "/opt/stackstorm-review/README.md"
        owner       = "root:root"
        permissions = "0644"
        content     = <<-EOT
          # StackStorm Single-Node Review Scaffold

          This host is intentionally unconfigured. Terraform does not install
          StackStorm or supporting packages, start services, register automation,
          or run an installation command.

          Before making a manual change:

          1. Confirm the operating system and StackStorm version are approved.
          2. Review package sources, signatures, dependencies, and rollback steps.
          3. Supply authentication, TLS, credentials, and license material through
             approved runtime stores, never through Terraform inputs or this file.
          4. Record a separate operator approval for installation and execution.

          Use SSM Session Manager for host access. Do not execute remotely fetched
          content directly in a shell. This file is guidance only and is not an
          installer or executable scaffold.
        EOT
      },
    ]
  }
}

resource "terraform_data" "configuration_guardrails" {
  count = var.enabled ? 1 : 0

  input = {
    purpose = "stackstorm-review-only"
  }

  lifecycle {
    precondition {
      condition     = var.subnet_id != null
      error_message = "subnet_id must identify an existing private subnet when the StackStorm runner is enabled."
    }

    precondition {
      condition     = var.create_iam_instance_profile != local.existing_instance_profile_set
      error_message = "Set exactly one SSM access path: iam_instance_profile_name or create_iam_instance_profile = true."
    }
  }
}

data "aws_ami" "approved_base" {
  count       = local.create_host ? 1 : 0
  most_recent = true
  owners      = var.ami_owner_ids

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
      condition     = startswith(self.name, "hc-security-base-") || startswith(self.name, "hc-base-")
      error_message = "The resolved AMI must be an approved hc-security-base-* or hc-base-* image."
    }
  }

  depends_on = [terraform_data.configuration_guardrails]
}

data "aws_subnet" "selected" {
  count = local.create_host ? 1 : 0
  id    = var.subnet_id

  depends_on = [terraform_data.configuration_guardrails]
}

data "aws_route_table" "selected" {
  count     = local.create_host ? 1 : 0
  subnet_id = var.subnet_id

  depends_on = [terraform_data.configuration_guardrails]
}

data "aws_ec2_instance_type" "selected" {
  count         = local.create_host ? 1 : 0
  instance_type = var.instance_type

  depends_on = [terraform_data.configuration_guardrails]
}

resource "aws_iam_role" "this" {
  count = local.should_create_instance_profile ? 1 : 0

  name                 = "${local.name}-role"
  permissions_boundary = var.iam_role_permissions_boundary_arn

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

resource "aws_iam_role_policy_attachment" "ssm" {
  count = local.should_create_instance_profile ? 1 : 0

  role       = aws_iam_role.this[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "this" {
  count = local.should_create_instance_profile ? 1 : 0

  name = "${local.name}-profile"
  role = aws_iam_role.this[0].name

  tags = merge(local.common_tags, { Name = "${local.name}-profile" })
}

resource "aws_security_group" "this" {
  count = local.create_host ? 1 : 0

  name_prefix            = "${local.name}-"
  description            = "Review-only StackStorm host; ingress is opt-in by restricted CIDR"
  vpc_id                 = data.aws_subnet.selected[0].vpc_id
  revoke_rules_on_delete = true

  tags = merge(local.common_tags, { Name = "${local.name}-sg" })

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [terraform_data.configuration_guardrails]
}

resource "aws_vpc_security_group_ingress_rule" "review" {
  for_each = local.create_host ? toset(local.review_access_cidrs) : toset([])

  security_group_id = aws_security_group.this[0].id
  description       = "Restricted StackStorm review access"
  from_port         = var.review_access_port
  to_port           = var.review_access_port
  ip_protocol       = "tcp"
  cidr_ipv4         = strcontains(each.value, ":") ? null : each.value
  cidr_ipv6         = strcontains(each.value, ":") ? each.value : null
}

resource "aws_vpc_security_group_egress_rule" "ssm_https" {
  count = local.create_host ? 1 : 0

  security_group_id = aws_security_group.this[0].id
  description       = "HTTPS egress for SSM endpoints and approved repositories"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_instance" "this" {
  count = local.create_host ? 1 : 0

  ami                         = data.aws_ami.approved_base[0].id
  instance_type               = var.instance_type
  subnet_id                   = data.aws_subnet.selected[0].id
  associate_public_ip_address = false
  vpc_security_group_ids      = [aws_security_group.this[0].id]
  iam_instance_profile        = local.instance_profile_name
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

  user_data                   = "#cloud-config\n${yamlencode(local.review_scaffold)}"
  user_data_replace_on_change = false

  tags = merge(local.common_tags, {
    Name = "${local.name}-host"
    Role = "stackstorm-review"
  })

  lifecycle {
    precondition {
      condition     = !data.aws_subnet.selected[0].map_public_ip_on_launch
      error_message = "subnet_id must not auto-assign public IPv4 addresses."
    }

    precondition {
      condition     = !data.aws_subnet.selected[0].assign_ipv6_address_on_creation
      error_message = "subnet_id must not auto-assign IPv6 addresses to the review host."
    }

    precondition {
      condition = alltrue([
        for route in data.aws_route_table.selected[0].routes :
        !try(startswith(route.gateway_id, "igw-"), false)
      ])
      error_message = "subnet_id must use a private route table without a direct internet-gateway route."
    }

    precondition {
      condition     = data.aws_ec2_instance_type.selected[0].default_vcpus >= 4
      error_message = "instance_type must provide at least 4 vCPUs for the single-node review host."
    }

    precondition {
      condition     = data.aws_ec2_instance_type.selected[0].memory_size >= 16384
      error_message = "instance_type must provide at least 16 GiB RAM for the single-node review host."
    }

    precondition {
      condition     = contains(data.aws_ec2_instance_type.selected[0].supported_architectures, "x86_64")
      error_message = "instance_type must support the x86_64 architecture used by the approved StackStorm base AMI."
    }

    precondition {
      condition     = local.instance_profile_name != null
      error_message = "An SSM-enabled IAM instance profile is required."
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.ssm,
    aws_vpc_security_group_egress_rule.ssm_https,
    terraform_data.configuration_guardrails,
  ]
}

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
  name        = "${var.name_prefix}-observability"
  common_tags = merge(var.tags, { NamePrefix = var.name_prefix, component = "observability-stack" })

  observability_ports = {
    prometheus = {
      label   = "Prometheus"
      port    = var.prometheus_port
      enabled = var.enable_prometheus_access
    }
    grafana = {
      label   = "Grafana"
      port    = var.grafana_port
      enabled = var.enable_grafana_access
    }
    loki = {
      label   = "Loki"
      port    = var.loki_port
      enabled = var.enable_loki_access
    }
    tempo = {
      label   = "Tempo"
      port    = var.tempo_port
      enabled = var.enable_tempo_access
    }
    otel_grpc = {
      label   = "OpenTelemetry OTLP gRPC"
      port    = var.otel_grpc_port
      enabled = var.enable_otel_grpc_access
    }
    otel_http = {
      label   = "OpenTelemetry OTLP HTTP"
      port    = var.otel_http_port
      enabled = var.enable_otel_http_access
    }
  }

  enabled_admin_ports = var.create_security_group && length(var.admin_cidr_blocks) > 0 ? {
    for name, service in local.observability_ports : name => service
    if service.enabled
  } : {}

  managed_security_group_ids = var.enabled && var.create_security_group ? [aws_security_group.this[0].id] : []
  instance_security_group_ids = concat(
    local.managed_security_group_ids,
    var.security_group_ids
  )
  should_create_instance_profile = var.enabled && var.create_iam_instance_profile && var.iam_instance_profile_name == null
  instance_profile_name          = local.should_create_instance_profile ? aws_iam_instance_profile.this[0].name : var.iam_instance_profile_name

  port_summary = join("\n", [
    for name, service in local.observability_ports :
    "- ${service.label}: ${service.port} (${service.enabled ? "eligible for admin CIDR ingress" : "not exposed by this module"})"
  ])

  cloud_init = {
    bootcmd = [
      "mkdir -p /opt/observability-stack",
    ]

    write_files = [
      {
        path        = "/opt/observability-stack/README.md"
        owner       = "root:root"
        permissions = "0644"
        content     = <<-EOT
          # Phase 4 Observability Scaffold

          This host is reserved for the Instana replacement stack:

          ${local.port_summary}

          Terraform intentionally does not auto-start the stack. Review the
          generated docker-compose.yml, add environment-specific scrape targets,
          credentials, retention settings, TLS, and data volumes, then start it
          with an approved operator process.

          Suggested operator flow:

          ```bash
          cd /opt/observability-stack
          docker compose --profile manual up -d
          ```

          Use SSM Session Manager for host access unless SSH was explicitly
          enabled with admin CIDRs.
        EOT
      },
      {
        path        = "/opt/observability-stack/docker-compose.yml"
        owner       = "root:root"
        permissions = "0640"
        content     = <<-EOT
          ---
          name: observability-stack
          services:
            prometheus:
              image: prom/prometheus:v2.55.1
              profiles: ["manual"]
              ports:
                - "${var.prometheus_port}:9090"
              volumes:
                - prometheus-data:/prometheus

            alertmanager:
              image: prom/alertmanager:v0.27.0
              profiles: ["manual"]
              ports:
                - "9093:9093"

            grafana:
              image: grafana/grafana:11.4.0
              profiles: ["manual"]
              ports:
                - "${var.grafana_port}:3000"
              volumes:
                - grafana-data:/var/lib/grafana

            loki:
              image: grafana/loki:3.3.2
              profiles: ["manual"]
              command: ["-config.file=/etc/loki/local-config.yaml"]
              ports:
                - "${var.loki_port}:3100"
              volumes:
                - loki-data:/loki

            tempo:
              image: grafana/tempo:2.6.1
              profiles: ["manual"]
              user: "0"
              ports:
                - "${var.tempo_port}:3200"
              volumes:
                - tempo-data:/tmp/tempo

            otel-collector:
              image: otel/opentelemetry-collector-contrib:0.116.1
              profiles: ["manual"]
              ports:
                - "${var.otel_grpc_port}:4317"
                - "${var.otel_http_port}:4318"

          volumes:
            prometheus-data:
            grafana-data:
            loki-data:
            tempo-data:
        EOT
      },
    ]

    runcmd = [
      "chmod 0750 /opt/observability-stack",
      "printf '%s\\n' 'Observability scaffold written to /opt/observability-stack. Review before starting services.' > /var/log/observability-stack-bootstrap.log",
    ]
  }
}

resource "aws_security_group" "this" {
  count = var.enabled && var.create_security_group ? 1 : 0

  name        = "${local.name}-sg"
  description = "Phase 4 observability host admin access"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = local.enabled_admin_ports

    content {
      description = "${ingress.value.label} from admin CIDRs"
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = "tcp"
      cidr_blocks = var.admin_cidr_blocks
    }
  }

  dynamic "ingress" {
    for_each = length(var.admin_cidr_blocks) > 0 && var.enable_ssh_access ? [1] : []

    content {
      description = "SSH from admin CIDRs"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = var.admin_cidr_blocks
    }
  }

  egress {
    description = "Allow outbound package, image, and telemetry access"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  revoke_rules_on_delete = true

  tags = merge(local.common_tags, { Name = "${local.name}-sg" })

  lifecycle {
    precondition {
      condition     = var.vpc_id != null
      error_message = "vpc_id must be set when create_security_group is true."
    }
  }
}

resource "aws_iam_role" "instance" {
  count = local.should_create_instance_profile ? 1 : 0

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
  count = local.should_create_instance_profile ? 1 : 0

  role       = aws_iam_role.instance[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "this" {
  count = local.should_create_instance_profile ? 1 : 0

  name = "${local.name}-instance-profile"
  role = aws_iam_role.instance[0].name

  tags = merge(local.common_tags, { Name = "${local.name}-instance-profile" })
}

resource "aws_instance" "this" {
  count = var.enabled ? 1 : 0

  ami                         = data.aws_ami.allowed_base[0].id
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = local.instance_security_group_ids
  iam_instance_profile        = local.instance_profile_name
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

  user_data                   = "#cloud-config\n${yamlencode(local.cloud_init)}"
  user_data_replace_on_change = false

  tags = merge(local.common_tags, {
    Name = "${local.name}-host"
    Role = "observability-stack"
  })

  lifecycle {
    precondition {
      condition     = var.subnet_id != null
      error_message = "subnet_id must be set when the observability host is enabled."
    }

    precondition {
      condition     = length(local.instance_security_group_ids) > 0
      error_message = "At least one security group is required. Leave create_security_group true or set security_group_ids."
    }
  }

  depends_on = [aws_iam_role_policy_attachment.ssm]
}

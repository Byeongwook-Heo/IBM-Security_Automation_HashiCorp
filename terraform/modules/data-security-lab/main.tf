data "aws_vpc" "default" {
  count   = var.enabled && var.vpc_id == null ? 1 : 0
  default = true
}

data "aws_subnets" "selected" {
  count = var.enabled && var.db_subnet_group_name == null && length(var.subnet_ids) == 0 ? 1 : 0

  filter {
    name   = "vpc-id"
    values = [local.vpc_id]
  }
}

locals {
  name                   = "${var.name_prefix}-data-security-lab"
  create_db_subnet_group = var.enabled && var.db_subnet_group_name == null
  vpc_id                 = var.enabled ? (var.vpc_id != null ? var.vpc_id : data.aws_vpc.default[0].id) : null
  subnet_ids             = var.enabled ? (length(var.subnet_ids) > 0 ? var.subnet_ids : (var.db_subnet_group_name == null ? data.aws_subnets.selected[0].ids : [])) : []
  db_subnet_group_name   = local.create_db_subnet_group ? aws_db_subnet_group.this[0].name : var.db_subnet_group_name
  common_tags            = merge(var.tags, { NamePrefix = var.name_prefix, component = "data-security-lab" })
  preload_libraries      = distinct(compact(concat(["pgaudit"], var.additional_shared_preload_libraries)))
}

resource "aws_security_group" "this" {
  count = var.enabled ? 1 : 0

  name        = "${local.name}-postgres-sg"
  description = "PostgreSQL access for the data security lab"
  vpc_id      = local.vpc_id

  dynamic "ingress" {
    for_each = length(var.allowed_cidr_blocks) > 0 ? [1] : []

    content {
      description = "PostgreSQL from approved CIDR blocks"
      from_port   = var.port
      to_port     = var.port
      protocol    = "tcp"
      cidr_blocks = var.allowed_cidr_blocks
    }
  }

  dynamic "ingress" {
    for_each = toset(var.allowed_security_group_ids)

    content {
      description     = "PostgreSQL from approved security group"
      from_port       = var.port
      to_port         = var.port
      protocol        = "tcp"
      security_groups = [ingress.value]
    }
  }

  egress {
    description = "Allow RDS managed egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  revoke_rules_on_delete = true

  tags = merge(local.common_tags, { Name = "${local.name}-postgres-sg" })
}

resource "aws_db_subnet_group" "this" {
  count = local.create_db_subnet_group ? 1 : 0

  name        = "${local.name}-subnets"
  description = "Subnet group for the data security lab PostgreSQL instance"
  subnet_ids  = local.subnet_ids

  tags = merge(local.common_tags, { Name = "${local.name}-subnets" })

  lifecycle {
    precondition {
      condition     = length(local.subnet_ids) > 0
      error_message = "subnet_ids must contain at least one subnet when db_subnet_group_name is not set."
    }
  }
}

resource "aws_db_parameter_group" "this" {
  count = var.enabled ? 1 : 0

  name        = "${local.name}-pg"
  description = "PostgreSQL pgAudit settings for the data security lab"
  family      = var.parameter_group_family

  parameter {
    name         = "shared_preload_libraries"
    value        = join(",", local.preload_libraries)
    apply_method = "pending-reboot"
  }

  parameter {
    name         = "pgaudit.log"
    value        = var.pgaudit_log_classes
    apply_method = "immediate"
  }

  parameter {
    name         = "pgaudit.log_catalog"
    value        = var.pgaudit_log_catalog ? "1" : "0"
    apply_method = "immediate"
  }

  parameter {
    name         = "pgaudit.log_parameter"
    value        = var.pgaudit_log_parameter ? "1" : "0"
    apply_method = "immediate"
  }

  parameter {
    name         = "pgaudit.log_statement_once"
    value        = var.pgaudit_log_statement_once ? "1" : "0"
    apply_method = "immediate"
  }

  parameter {
    name         = "log_connections"
    value        = var.log_connections ? "1" : "0"
    apply_method = "immediate"
  }

  parameter {
    name         = "log_disconnections"
    value        = var.log_disconnections ? "1" : "0"
    apply_method = "immediate"
  }

  parameter {
    name         = "log_min_duration_statement"
    value        = tostring(var.log_min_duration_statement_ms)
    apply_method = "immediate"
  }

  tags = merge(local.common_tags, { Name = "${local.name}-pg" })
}

resource "aws_db_instance" "this" {
  count = var.enabled ? 1 : 0

  identifier     = local.name
  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class

  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage > 0 ? var.max_allocated_storage : null
  storage_type          = var.storage_type
  storage_encrypted     = var.storage_encrypted
  kms_key_id            = var.kms_key_id

  db_name  = var.db_name
  username = var.admin_username
  password = var.manage_master_user_password ? null : var.master_password
  port     = var.port

  manage_master_user_password   = var.manage_master_user_password
  master_user_secret_kms_key_id = var.master_user_secret_kms_key_id

  db_subnet_group_name            = local.db_subnet_group_name
  vpc_security_group_ids          = concat([aws_security_group.this[0].id], var.additional_security_group_ids)
  parameter_group_name            = aws_db_parameter_group.this[0].name
  publicly_accessible             = var.publicly_accessible
  multi_az                        = var.multi_az
  backup_retention_period         = var.backup_retention_period
  backup_window                   = var.backup_window
  maintenance_window              = var.maintenance_window
  auto_minor_version_upgrade      = var.auto_minor_version_upgrade
  apply_immediately               = var.apply_immediately
  deletion_protection             = var.deletion_protection
  skip_final_snapshot             = var.skip_final_snapshot
  final_snapshot_identifier       = var.skip_final_snapshot ? null : coalesce(var.final_snapshot_identifier, "${local.name}-final")
  copy_tags_to_snapshot           = true
  enabled_cloudwatch_logs_exports = var.enabled_cloudwatch_logs_exports

  tags = merge(local.common_tags, { Name = local.name, Role = "data-security-lab-postgres" })

  lifecycle {
    precondition {
      condition     = var.db_subnet_group_name != null || length(local.subnet_ids) > 0
      error_message = "Set db_subnet_group_name or provide subnet_ids for a new DB subnet group."
    }

    precondition {
      condition     = var.manage_master_user_password || var.master_password != null
      error_message = "Set master_password when manage_master_user_password is false."
    }
  }
}

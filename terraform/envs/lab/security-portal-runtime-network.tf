variable "security_portal_runtime_create_data_subnets" {
  description = "Create two dedicated private subnets and local-only route tables for portal RDS and Valkey."
  type        = bool
  default     = false
}

variable "security_portal_runtime_data_subnets" {
  description = "Dedicated portal data subnet definitions. CIDRs must be unused ranges inside the portal VPC."
  type = map(object({
    availability_zone = string
    cidr_block        = string
  }))
  default = {
    a = {
      availability_zone = "ap-northeast-2a"
      cidr_block        = "172.31.64.0/24"
    }
    b = {
      availability_zone = "ap-northeast-2b"
      cidr_block        = "172.31.65.0/24"
    }
  }

  validation {
    condition = length(var.security_portal_runtime_data_subnets) >= 2 && alltrue([
      for subnet in values(var.security_portal_runtime_data_subnets) :
      can(cidrhost(subnet.cidr_block, 0)) &&
      !strcontains(subnet.cidr_block, ":") &&
      can(regex("^ap-northeast-2[a-d]$", subnet.availability_zone))
    ])
    error_message = "Provide at least two valid IPv4 subnet definitions in distinct ap-northeast-2 Availability Zones."
  }

  validation {
    condition = length(distinct([
      for subnet in values(var.security_portal_runtime_data_subnets) :
      subnet.availability_zone
    ])) == length(var.security_portal_runtime_data_subnets)
    error_message = "Each dedicated portal data subnet must use a distinct Availability Zone."
  }

  validation {
    condition = length(distinct([
      for subnet in values(var.security_portal_runtime_data_subnets) :
      subnet.cidr_block
    ])) == length(var.security_portal_runtime_data_subnets)
    error_message = "Dedicated portal data subnet CIDRs must be unique."
  }
}

locals {
  create_security_portal_runtime_data_subnets = (
    var.enable_security_portal_runtime &&
    var.security_portal_runtime_create_data_subnets
  )
  security_portal_runtime_data_subnet_ids = local.create_security_portal_runtime_data_subnets ? [
    for key in sort(keys(var.security_portal_runtime_data_subnets)) :
    aws_subnet.security_portal_runtime_data[key].id
  ] : var.security_portal_runtime_db_subnet_ids
}

resource "aws_subnet" "security_portal_runtime_data" {
  for_each = local.create_security_portal_runtime_data_subnets ? var.security_portal_runtime_data_subnets : {}

  vpc_id                  = var.security_portal_runtime_vpc_id
  availability_zone       = each.value.availability_zone
  cidr_block              = each.value.cidr_block
  map_public_ip_on_launch = false

  tags = merge(var.tags, {
    Name        = "${var.name_prefix}-portal-data-${each.key}"
    application = "security-portal"
    component   = "managed-data"
    managed_by  = "terraform"
  })

  lifecycle {
    precondition {
      condition     = var.security_portal_runtime_vpc_id != null
      error_message = "security_portal_runtime_vpc_id is required when creating dedicated data subnets."
    }
  }
}

resource "aws_route_table" "security_portal_runtime_data" {
  for_each = aws_subnet.security_portal_runtime_data

  vpc_id = var.security_portal_runtime_vpc_id

  tags = merge(var.tags, {
    Name        = "${var.name_prefix}-portal-data-${each.key}"
    application = "security-portal"
    component   = "managed-data"
    managed_by  = "terraform"
  })
}

resource "aws_route_table_association" "security_portal_runtime_data" {
  for_each = aws_subnet.security_portal_runtime_data

  subnet_id      = each.value.id
  route_table_id = aws_route_table.security_portal_runtime_data[each.key].id
}

output "security_portal_runtime_data_subnet_ids" {
  description = "Dedicated private subnet IDs used by portal RDS and Valkey."
  value       = local.security_portal_runtime_data_subnet_ids
}

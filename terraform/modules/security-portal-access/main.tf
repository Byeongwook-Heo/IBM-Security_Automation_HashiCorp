locals {
  portal_domain   = var.portal_domain_name == null ? null : lower(trimspace(var.portal_domain_name))
  keycloak_domain = var.keycloak_domain_name == null ? null : lower(trimspace(var.keycloak_domain_name))
  zone_name       = var.route53_zone_name == null ? null : "${trimsuffix(lower(trimspace(var.route53_zone_name)), ".")}."

  certificate_configured = var.create_certificate || var.certificate_arn != null
  edge_enabled = (
    var.enabled
    && local.portal_domain != null
    && local.zone_name != null
    && local.certificate_configured
    && var.portal_target_instance_id != null
  )
  create_certificate    = local.edge_enabled && var.create_certificate
  keycloak_edge_enabled = local.edge_enabled && local.keycloak_domain != null && var.keycloak_alb_name != null

  common_tags = merge(var.tags, {
    component = "security-portal-access"
  })
}

data "aws_route53_zone" "public" {
  count = local.edge_enabled ? 1 : 0

  name         = local.zone_name
  private_zone = false
}

data "aws_instance" "portal" {
  count = local.edge_enabled ? 1 : 0

  instance_id = var.portal_target_instance_id
}

data "aws_subnet" "portal" {
  count = local.edge_enabled ? 1 : 0

  id = data.aws_instance.portal[0].subnet_id
}

data "aws_subnet" "alb" {
  for_each = local.edge_enabled ? toset(var.portal_alb_subnet_ids) : toset([])

  id = each.value
}

data "aws_lb" "keycloak" {
  count = local.keycloak_edge_enabled ? 1 : 0

  name = var.keycloak_alb_name
}

data "aws_lb_listener" "keycloak_http" {
  count = local.keycloak_edge_enabled ? 1 : 0

  load_balancer_arn = data.aws_lb.keycloak[0].arn
  port              = 80
}

data "aws_caller_identity" "current" {
  count = local.edge_enabled ? 1 : 0
}

data "aws_region" "current" {
  count = local.edge_enabled ? 1 : 0
}

data "aws_partition" "current" {
  count = local.edge_enabled ? 1 : 0
}

locals {
  portal_target_security_group_id = var.portal_target_security_group_id != null ? var.portal_target_security_group_id : try(tolist(data.aws_instance.portal[0].vpc_security_group_ids)[0], null)
  portal_vpc_id                   = try(data.aws_subnet.portal[0].vpc_id, null)
  alb_vpc_ids                     = distinct([for subnet in data.aws_subnet.alb : subnet.vpc_id])
  alb_availability_zones          = distinct([for subnet in data.aws_subnet.alb : subnet.availability_zone])
  keycloak_target_group_arn = var.keycloak_target_group_arn != null ? var.keycloak_target_group_arn : try(
    one([
      for action in data.aws_lb_listener.keycloak_http[0].default_action :
      action.target_group_arn if action.type == "forward" && action.target_group_arn != null
    ]),
    null
  )
}

resource "terraform_data" "guardrails" {
  count = local.edge_enabled ? 1 : 0

  input = {
    portal_domain   = local.portal_domain
    keycloak_domain = local.keycloak_domain
  }

  lifecycle {
    precondition {
      condition     = length(var.portal_alb_subnet_ids) >= 2 && length(local.alb_availability_zones) >= 2
      error_message = "portal_alb_subnet_ids must include at least two subnets in distinct Availability Zones."
    }

    precondition {
      condition     = length(local.alb_vpc_ids) == 1 && try(local.alb_vpc_ids[0], null) == local.portal_vpc_id
      error_message = "All portal ALB subnets and the portal EC2 instance must be in the same VPC."
    }

    precondition {
      condition     = contains(local.alb_availability_zones, data.aws_subnet.portal[0].availability_zone)
      error_message = "portal_alb_subnet_ids must enable the Availability Zone that contains the portal EC2 target."
    }

    precondition {
      condition     = local.portal_target_security_group_id != null
      error_message = "The portal target must have an attached security group or portal_target_security_group_id must be supplied."
    }

    precondition {
      condition     = length(var.allowed_cidr_blocks) > 0
      error_message = "allowed_cidr_blocks must contain at least one restricted administrator CIDR."
    }

    precondition {
      condition     = var.create_certificate != (var.certificate_arn != null)
      error_message = "Set exactly one certificate source: create_certificate=true or certificate_arn."
    }

    precondition {
      condition     = !local.keycloak_edge_enabled || local.keycloak_target_group_arn != null
      error_message = "The existing Keycloak HTTP listener must forward to a target group, or keycloak_target_group_arn must be supplied."
    }
  }
}

resource "aws_acm_certificate" "edge" {
  count = local.create_certificate ? 1 : 0

  domain_name               = local.portal_domain
  subject_alternative_names = compact([local.keycloak_domain])
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-portal-edge" })
}

resource "aws_route53_record" "certificate_validation" {
  for_each = local.create_certificate ? {
    for option in aws_acm_certificate.edge[0].domain_validation_options :
    option.domain_name => {
      name   = option.resource_record_name
      record = option.resource_record_value
      type   = option.resource_record_type
    }
  } : {}

  allow_overwrite = true
  zone_id         = data.aws_route53_zone.public[0].zone_id
  name            = each.value.name
  type            = each.value.type
  ttl             = 60
  records         = [each.value.record]
}

resource "aws_acm_certificate_validation" "edge" {
  count = local.create_certificate ? 1 : 0

  certificate_arn         = aws_acm_certificate.edge[0].arn
  validation_record_fqdns = [for record in aws_route53_record.certificate_validation : record.fqdn]
}

locals {
  certificate_arn = var.certificate_arn != null ? var.certificate_arn : try(aws_acm_certificate_validation.edge[0].certificate_arn, null)
}

resource "aws_security_group" "portal_alb" {
  count = local.edge_enabled ? 1 : 0

  name_prefix            = "${var.name_prefix}-portal-edge-"
  description            = "Restricted HTTPS edge for the Security Portal"
  vpc_id                 = local.portal_vpc_id
  revoke_rules_on_delete = true

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-portal-edge-sg" })

  depends_on = [terraform_data.guardrails]
}

resource "aws_vpc_security_group_ingress_rule" "portal_https" {
  for_each = local.edge_enabled ? toset(var.allowed_cidr_blocks) : toset([])

  security_group_id = aws_security_group.portal_alb[0].id
  description       = "Restricted portal HTTPS access"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = strcontains(each.value, ":") ? null : each.value
  cidr_ipv6         = strcontains(each.value, ":") ? each.value : null
}

resource "aws_vpc_security_group_ingress_rule" "portal_http_redirect" {
  for_each = local.edge_enabled ? toset(var.allowed_cidr_blocks) : toset([])

  security_group_id = aws_security_group.portal_alb[0].id
  description       = "Restricted portal HTTP redirect"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  cidr_ipv4         = strcontains(each.value, ":") ? null : each.value
  cidr_ipv6         = strcontains(each.value, ":") ? each.value : null
}

resource "aws_vpc_security_group_egress_rule" "portal_target" {
  count = local.edge_enabled ? 1 : 0

  security_group_id            = aws_security_group.portal_alb[0].id
  description                  = "Portal ALB to the existing portal target"
  from_port                    = var.portal_target_port
  to_port                      = var.portal_target_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = local.portal_target_security_group_id
}

resource "aws_vpc_security_group_ingress_rule" "portal_from_alb" {
  count = local.edge_enabled ? 1 : 0

  security_group_id            = local.portal_target_security_group_id
  description                  = "Dedicated portal ALB to the portal service"
  from_port                    = var.portal_target_port
  to_port                      = var.portal_target_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.portal_alb[0].id
}

resource "aws_s3_bucket" "portal_access_logs" {
  count = local.edge_enabled ? 1 : 0

  bucket = "${substr(var.name_prefix, 0, 12)}-p-alb-${data.aws_caller_identity.current[0].account_id}-${data.aws_region.current[0].name}"

  tags = merge(local.common_tags, {
    Name    = "${var.name_prefix}-portal-alb-access-logs"
    purpose = "portal-alb-access-logs"
  })
}

resource "aws_s3_bucket_public_access_block" "portal_access_logs" {
  count = local.edge_enabled ? 1 : 0

  bucket                  = aws_s3_bucket.portal_access_logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "portal_access_logs" {
  count = local.edge_enabled ? 1 : 0

  bucket = aws_s3_bucket.portal_access_logs[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "portal_access_logs" {
  count = local.edge_enabled ? 1 : 0

  bucket = aws_s3_bucket.portal_access_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "portal_access_logs" {
  count = local.edge_enabled ? 1 : 0

  bucket = aws_s3_bucket.portal_access_logs[0].id

  rule {
    id     = "expire-portal-alb-access-logs"
    status = "Enabled"

    filter {
      prefix = "portal/"
    }

    expiration {
      days = var.access_log_retention_days
    }
  }
}

data "aws_iam_policy_document" "portal_access_logs" {
  count = local.edge_enabled ? 1 : 0

  statement {
    sid     = "AllowAlbLogDelivery"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.portal_access_logs[0].arn}/portal/AWSLogs/${data.aws_caller_identity.current[0].account_id}/*"
    ]

    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values = [
        "arn:${data.aws_partition.current[0].partition}:elasticloadbalancing:${data.aws_region.current[0].name}:${data.aws_caller_identity.current[0].account_id}:loadbalancer/*"
      ]
    }
  }
}

resource "aws_s3_bucket_policy" "portal_access_logs" {
  count = local.edge_enabled ? 1 : 0

  bucket = aws_s3_bucket.portal_access_logs[0].id
  policy = data.aws_iam_policy_document.portal_access_logs[0].json

  depends_on = [aws_s3_bucket_public_access_block.portal_access_logs]
}

resource "aws_lb" "portal" {
  count = local.edge_enabled ? 1 : 0

  name                       = "${var.name_prefix}-portal-edge"
  load_balancer_type         = "application"
  internal                   = false
  security_groups            = [aws_security_group.portal_alb[0].id]
  subnets                    = var.portal_alb_subnet_ids
  drop_invalid_header_fields = true

  access_logs {
    bucket  = aws_s3_bucket.portal_access_logs[0].id
    prefix  = "portal"
    enabled = true
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-portal-edge" })

  depends_on = [
    terraform_data.guardrails,
    aws_s3_bucket_policy.portal_access_logs,
  ]
}

resource "aws_lb_target_group" "portal" {
  count = local.edge_enabled ? 1 : 0

  name        = "${var.name_prefix}-portal-edge"
  port        = var.portal_target_port
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = local.portal_vpc_id

  health_check {
    enabled             = true
    path                = "/health"
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-portal-edge" })

  depends_on = [terraform_data.guardrails]
}

resource "aws_lb_target_group_attachment" "portal" {
  count = local.edge_enabled ? 1 : 0

  target_group_arn = aws_lb_target_group.portal[0].arn
  target_id        = data.aws_instance.portal[0].id
  port             = var.portal_target_port
}

resource "aws_lb_listener" "portal_http" {
  count = local.edge_enabled ? 1 : 0

  load_balancer_arn = aws_lb.portal[0].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "portal_https" {
  count = local.edge_enabled ? 1 : 0

  load_balancer_arn = aws_lb.portal[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = local.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.portal[0].arn
  }
}

resource "aws_route53_record" "portal" {
  count = local.edge_enabled ? 1 : 0

  zone_id = data.aws_route53_zone.public[0].zone_id
  name    = local.portal_domain
  type    = "A"

  alias {
    name                   = aws_lb.portal[0].dns_name
    zone_id                = aws_lb.portal[0].zone_id
    evaluate_target_health = true
  }
}

locals {
  keycloak_https_ingress = local.keycloak_edge_enabled ? {
    for pair in setproduct(toset(data.aws_lb.keycloak[0].security_groups), toset(var.allowed_cidr_blocks)) :
    "${pair[0]}:${pair[1]}" => {
      security_group_id = pair[0]
      cidr              = pair[1]
    }
  } : {}
}

resource "aws_vpc_security_group_ingress_rule" "keycloak_https" {
  for_each = local.keycloak_https_ingress

  security_group_id = each.value.security_group_id
  description       = "Restricted Keycloak HTTPS access"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = strcontains(each.value.cidr, ":") ? null : each.value.cidr
  cidr_ipv6         = strcontains(each.value.cidr, ":") ? each.value.cidr : null
}

resource "aws_eip" "portal_egress" {
  count = local.keycloak_edge_enabled ? 1 : 0

  domain = "vpc"

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-portal-egress" })
}

resource "aws_vpc_security_group_ingress_rule" "keycloak_https_from_portal" {
  for_each = local.keycloak_edge_enabled ? toset(data.aws_lb.keycloak[0].security_groups) : toset([])

  security_group_id = each.value
  description       = "Keycloak HTTPS from the Security Portal static egress"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "${aws_eip.portal_egress[0].public_ip}/32"

  depends_on = [terraform_data.guardrails]
}

resource "aws_eip_association" "portal_egress" {
  count = local.keycloak_edge_enabled ? 1 : 0

  allocation_id       = aws_eip.portal_egress[0].id
  instance_id         = data.aws_instance.portal[0].id
  allow_reassociation = true

  depends_on = [aws_vpc_security_group_ingress_rule.keycloak_https_from_portal]
}

resource "aws_lb_listener" "keycloak_https" {
  count = local.keycloak_edge_enabled ? 1 : 0

  load_balancer_arn = data.aws_lb.keycloak[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = local.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = local.keycloak_target_group_arn
  }

  depends_on = [terraform_data.guardrails]
}

resource "aws_lb_listener_rule" "keycloak_http_redirect" {
  count = local.keycloak_edge_enabled ? 1 : 0

  listener_arn = data.aws_lb_listener.keycloak_http[0].arn
  priority     = var.keycloak_http_redirect_priority

  action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }

  condition {
    host_header {
      values = [local.keycloak_domain]
    }
  }
}

resource "aws_route53_record" "keycloak" {
  count = local.keycloak_edge_enabled ? 1 : 0

  zone_id = data.aws_route53_zone.public[0].zone_id
  name    = local.keycloak_domain
  type    = "A"

  alias {
    name                   = data.aws_lb.keycloak[0].dns_name
    zone_id                = data.aws_lb.keycloak[0].zone_id
    evaluate_target_health = true
  }
}

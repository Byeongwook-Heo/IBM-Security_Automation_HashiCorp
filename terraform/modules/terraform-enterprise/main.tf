data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "allowed_base" {
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
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  azs         = slice(data.aws_availability_zones.available.names, 0, 2)
  name        = "${var.name_prefix}-tfe"
  common_tags = merge(var.tags, { NamePrefix = local.name, component = "terraform-enterprise" })
  bucket_name = lower("${local.name}-${data.aws_caller_identity.current.account_id}-${var.region}")
}

resource "aws_vpc" "this" {
  count = var.enabled ? 1 : 0

  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.common_tags, { Name = "${local.name}-vpc" })
}

resource "aws_internet_gateway" "this" {
  count = var.enabled ? 1 : 0

  vpc_id = aws_vpc.this[0].id

  tags = merge(local.common_tags, { Name = "${local.name}-igw" })
}

resource "aws_subnet" "public" {
  count = var.enabled ? 2 : 0

  vpc_id                  = aws_vpc.this[0].id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = true

  tags = merge(local.common_tags, {
    Name = "${local.name}-public-${local.azs[count.index]}"
    Tier = "public"
  })
}

resource "aws_subnet" "private" {
  count = var.enabled ? 2 : 0

  vpc_id            = aws_vpc.this[0].id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = local.azs[count.index]

  tags = merge(local.common_tags, {
    Name = "${local.name}-private-${local.azs[count.index]}"
    Tier = "private"
  })
}

resource "aws_subnet" "database" {
  count = var.enabled ? 2 : 0

  vpc_id            = aws_vpc.this[0].id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 20)
  availability_zone = local.azs[count.index]

  tags = merge(local.common_tags, {
    Name = "${local.name}-db-${local.azs[count.index]}"
    Tier = "database"
  })
}

resource "aws_eip" "nat" {
  count = var.enabled ? 1 : 0

  domain = "vpc"

  tags = merge(local.common_tags, { Name = "${local.name}-nat-eip" })
}

resource "aws_nat_gateway" "this" {
  count = var.enabled ? 1 : 0

  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id

  tags = merge(local.common_tags, { Name = "${local.name}-nat" })

  depends_on = [aws_internet_gateway.this]
}

resource "aws_route_table" "public" {
  count = var.enabled ? 1 : 0

  vpc_id = aws_vpc.this[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this[0].id
  }

  tags = merge(local.common_tags, { Name = "${local.name}-public-rt" })
}

resource "aws_route_table_association" "public" {
  count = var.enabled ? 2 : 0

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table" "private" {
  count = var.enabled ? 1 : 0

  vpc_id = aws_vpc.this[0].id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.this[0].id
  }

  tags = merge(local.common_tags, { Name = "${local.name}-private-rt" })
}

resource "aws_route_table_association" "private" {
  count = var.enabled ? 2 : 0

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[0].id
}

resource "aws_route_table_association" "database" {
  count = var.enabled ? 2 : 0

  subnet_id      = aws_subnet.database[count.index].id
  route_table_id = aws_route_table.private[0].id
}

resource "aws_security_group" "alb" {
  count = var.enabled ? 1 : 0

  name        = "${local.name}-alb-sg"
  description = "Public ALB access for Terraform Enterprise"
  vpc_id      = aws_vpc.this[0].id

  dynamic "ingress" {
    for_each = length(var.alb_allowed_cidr_blocks) > 0 ? [1] : []

    content {
      description = "HTTP redirect from approved administrators"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = var.alb_allowed_cidr_blocks
    }
  }

  dynamic "ingress" {
    for_each = length(var.alb_allowed_cidr_blocks) > 0 ? [1] : []

    content {
      description = "HTTPS from approved administrators"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = var.alb_allowed_cidr_blocks
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${local.name}-alb-sg" })

  lifecycle {
    precondition {
      condition     = !var.enabled || length(var.alb_allowed_cidr_blocks) > 0
      error_message = "Terraform Enterprise requires at least one explicit restricted ALB CIDR."
    }
  }
}

resource "aws_security_group" "tfe" {
  count = var.enabled ? 1 : 0

  name        = "${local.name}-instance-sg"
  description = "Terraform Enterprise host access"
  vpc_id      = aws_vpc.this[0].id

  ingress {
    description     = "TFE HTTP from ALB"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb[0].id]
  }

  ingress {
    description     = "TFE HTTPS from ALB"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.alb[0].id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${local.name}-instance-sg" })
}

resource "aws_security_group" "database" {
  count = var.enabled ? 1 : 0

  name        = "${local.name}-db-sg"
  description = "Terraform Enterprise PostgreSQL access"
  vpc_id      = aws_vpc.this[0].id

  ingress {
    description     = "PostgreSQL from TFE"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.tfe[0].id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${local.name}-db-sg" })
}

resource "aws_s3_bucket" "object_storage" {
  count = var.enabled ? 1 : 0

  bucket = local.bucket_name

  tags = merge(local.common_tags, { Name = "${local.name}-object-storage" })
}

resource "aws_s3_bucket_public_access_block" "object_storage" {
  count = var.enabled ? 1 : 0

  bucket                  = aws_s3_bucket.object_storage[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "object_storage" {
  count = var.enabled ? 1 : 0

  bucket = aws_s3_bucket.object_storage[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "object_storage" {
  count = var.enabled ? 1 : 0

  bucket = aws_s3_bucket.object_storage[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_db_subnet_group" "this" {
  count = var.enabled ? 1 : 0

  name       = "${local.name}-db-subnets"
  subnet_ids = aws_subnet.database[*].id

  tags = merge(local.common_tags, { Name = "${local.name}-db-subnets" })
}

resource "aws_db_instance" "this" {
  count = var.enabled ? 1 : 0

  identifier                  = "${local.name}-postgres"
  engine                      = "postgres"
  engine_version              = "16"
  instance_class              = "db.t4g.small"
  allocated_storage           = 50
  max_allocated_storage       = 100
  db_name                     = "tfe"
  username                    = "tfeadmin"
  manage_master_user_password = true
  db_subnet_group_name        = aws_db_subnet_group.this[0].name
  vpc_security_group_ids      = [aws_security_group.database[0].id]
  storage_encrypted           = true
  backup_retention_period     = 1
  deletion_protection         = false
  skip_final_snapshot         = true
  publicly_accessible         = false

  tags = merge(local.common_tags, { Name = "${local.name}-postgres" })
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

resource "aws_iam_role_policy" "instance" {
  count = var.enabled ? 1 : 0

  name = "${local.name}-runtime"
  role = aws_iam_role.instance[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.object_storage[0].arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:AbortMultipartUpload",
          "s3:ListMultipartUploadParts"
        ]
        Resource = "${aws_s3_bucket.object_storage[0].arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          var.license_secret_arn,
          var.encryption_password_secret_arn,
          aws_db_instance.this[0].master_user_secret[0].secret_arn
        ]
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

resource "aws_lb" "this" {
  count = var.enabled ? 1 : 0

  name               = "${local.name}-alb"
  load_balancer_type = "application"
  internal           = false
  security_groups    = [aws_security_group.alb[0].id]
  subnets            = aws_subnet.public[*].id

  tags = merge(local.common_tags, { Name = "${local.name}-alb" })
}

resource "tls_private_key" "alb" {
  count = var.enabled ? 1 : 0

  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "alb" {
  count = var.enabled ? 1 : 0

  private_key_pem = tls_private_key.alb[0].private_key_pem
  dns_names       = [aws_lb.this[0].dns_name]

  subject {
    common_name  = aws_lb.this[0].dns_name
    organization = "IBM HashiCorp Lab"
  }

  validity_period_hours = 8760
  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "server_auth"
  ]
}

resource "aws_acm_certificate" "alb" {
  count = var.enabled ? 1 : 0

  private_key      = tls_private_key.alb[0].private_key_pem
  certificate_body = tls_self_signed_cert.alb[0].cert_pem

  tags = merge(local.common_tags, { Name = "${local.name}-alb-self-signed" })
}

resource "aws_lb_target_group" "tfe" {
  count = var.enabled ? 1 : 0

  name     = "${local.name}-tg"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = aws_vpc.this[0].id

  health_check {
    enabled             = true
    path                = "/api/v1/health/readiness"
    protocol            = "HTTPS"
    matcher             = "200"
    interval            = 30
    timeout             = 10
    healthy_threshold   = 2
    unhealthy_threshold = 5
  }

  tags = merge(local.common_tags, { Name = "${local.name}-tg" })
}

resource "aws_lb_listener" "http" {
  count = var.enabled ? 1 : 0

  load_balancer_arn = aws_lb.this[0].arn
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

resource "aws_lb_listener" "https" {
  count = var.enabled ? 1 : 0

  load_balancer_arn = aws_lb.this[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.alb[0].arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tfe[0].arn
  }
}

resource "aws_instance" "this" {
  count = var.enabled ? 1 : 0

  ami                         = data.aws_ami.allowed_base.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.private[0].id
  vpc_security_group_ids      = [aws_security_group.tfe[0].id]
  iam_instance_profile        = aws_iam_instance_profile.this[0].name
  associate_public_ip_address = false

  root_block_device {
    volume_size = 120
    volume_type = "gp3"
    encrypted   = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/templates/user_data.sh.tftpl", {
    region                         = var.region
    tfe_hostname                   = aws_lb.this[0].dns_name
    tfe_image_tag                  = var.tfe_image_tag
    license_secret_arn             = var.license_secret_arn
    encryption_password_secret_arn = var.encryption_password_secret_arn
    db_secret_arn                  = aws_db_instance.this[0].master_user_secret[0].secret_arn
    db_host                        = aws_db_instance.this[0].address
    db_name                        = aws_db_instance.this[0].db_name
    db_user                        = aws_db_instance.this[0].username
    s3_bucket                      = aws_s3_bucket.object_storage[0].bucket
    vpc_cidr                       = var.vpc_cidr
  })

  tags = merge(local.common_tags, {
    Name = "${local.name}-host"
    Role = "terraform-enterprise"
  })

  depends_on = [
    aws_iam_role_policy_attachment.ssm,
    aws_iam_role_policy.instance,
    aws_nat_gateway.this
  ]
}

resource "aws_lb_target_group_attachment" "tfe" {
  count = var.enabled ? 1 : 0

  target_group_arn = aws_lb_target_group.tfe[0].arn
  target_id        = aws_instance.this[0].id
  port             = 443
}

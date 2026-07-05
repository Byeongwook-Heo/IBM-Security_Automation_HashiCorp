package terraform.security

deny[msg] { input.resource_type == "aws_s3_bucket_public_access_block"; input.public == true; msg := "public S3 buckets are forbidden" }
deny[msg] { input.cidr == "0.0.0.0/0"; input.port == 22; msg := "wide-open SSH is forbidden" }
deny[msg] { input.resource_type == "aws_db_instance"; not input.storage_encrypted; msg := "unencrypted RDS is forbidden" }
required_tags := {"owner","application","environment","data_classification","cost_center","managed_by"}

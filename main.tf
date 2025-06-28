# 0. Get AWS Account ID
#############################
data "aws_caller_identity" "current" {}

# 1. Strong Password Policy
#####################
resource "aws_iam_account_password_policy" "strong_password_policy" {
  minimum_password_length        = 12
  require_symbols                = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 5
  hard_expiry                    = true
}

# 2. Create IAM User
resource "aws_iam_user" "new_user" {
  name = "readonly-ec2-user"
  tags = {
    Department  = "Admin"
    Environment = "Dev"
    Project     = "Company-Wide"
  }
}

# 3. Attach Least-Privilege Policy

resource "aws_iam_policy" "ec2_describe_policy" {
  name        = "ec2_describe_policy"
  description = "Allow EC2 Describe actions only"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action   = ["ec2:Describe*"],
        Effect   = "Allow",
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy_attachment" "attach_policy" {
  name       = "attach-ec2-describe"
  users      = [aws_iam_user.new_user.name]
  policy_arn = aws_iam_policy.ec2_describe_policy.arn
}


# 4. Optional: Access Key for CLI/API
resource "aws_iam_access_key" "new_user_access_key" {
  user = aws_iam_user.new_user.name
  lifecycle {
    prevent_destroy = false
  }
}

#############################
# KMS Key for Secrets Encryption
#############################
resource "aws_kms_key" "secrets_kms" {
  description             = "KMS key for encrypting IAM user secrets"
  enable_key_rotation     = true
  deletion_window_in_days = 10
}

resource "aws_kms_alias" "secrets_kms_alias" {
  name          = "alias/iam-user-secrets"
  target_key_id = aws_kms_key.secrets_kms.key_id
}

#############################
# Secrets Manager Secret
#############################
resource "aws_secretsmanager_secret" "iam_user_secret" {
  name        = "iam-user-${aws_iam_user.new_user.name}-credentials"
  description = "Access key for IAM user ${aws_iam_user.new_user.name}"
  kms_key_id  = aws_kms_key.secrets_kms.arn

  tags = {
    Purpose     = "IAM User Credentials"
    Environment = "Dev"
    Owner       = "SecOps"
  }
}

#############################
# Secrets Manager Secret Version
#############################
resource "aws_secretsmanager_secret_version" "iam_user_secret_version" {
  secret_id = aws_secretsmanager_secret.iam_user_secret.id

  secret_string = jsonencode({
    access_key_id     = aws_iam_access_key.new_user_access_key.id
    secret_access_key = aws_iam_access_key.new_user_access_key.secret
  })

  depends_on = [aws_iam_access_key.new_user_access_key]
}


# 6. CloudTrail for Auditing
#####################

resource "random_id" "bucket_suffix" {
  keepers = {
    iam_user = aws_iam_user.new_user.name
  }
  byte_length = 4
}

resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket = "company-cloudtrail-logs-${random_id.bucket_suffix.hex}"
  tags = {
    Purpose     = "CloudTrail Logs"
    Environment = "Dev"
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}


resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.secrets_kms.arn
    }
  }
}


resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid : "AWSCloudTrailAclCheck",
        Effect : "Allow",
        Principal : {
          Service : "cloudtrail.amazonaws.com"
        },
        Action : "s3:GetBucketAcl",
        Resource : "arn:aws:s3:::${aws_s3_bucket.cloudtrail_bucket.id}"
      },
      {
        Sid : "AWSCloudTrailWrite",
        Effect : "Allow",
        Principal : {
          Service : "cloudtrail.amazonaws.com"
        },
        Action : "s3:PutObject",
        Resource : "arn:aws:s3:::${aws_s3_bucket.cloudtrail_bucket.id}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
        Condition : {
          StringEquals : {
            "s3:x-amz-acl" : "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "company-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::${aws_s3_bucket.cloudtrail_bucket.id}/"]
    }
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_policy]
}
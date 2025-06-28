# Terraform AWS IAM & CloudTrail Setup

## Overview

This Terraform module provisions:

- ✅ A strong IAM password policy
- ✅ A least-privilege IAM user with EC2 Describe-only access
- ✅ Secure access key generation stored in AWS Secrets Manager (encrypted with KMS)
- ✅ A secure S3 bucket (KMS-encrypted, public access blocked) for CloudTrail logs

---

## Resources Created

| Resource Type                          | Purpose                                                       |
|----------------------------------------|---------------------------------------------------------------|
| `aws_iam_account_password_policy`      | Enforces strong password rules across the AWS account         |
| `aws_iam_user`                         | Creates a new IAM user (`readonly-ec2-user`)                  |
| `aws_iam_policy`                       | EC2 Describe-only policy                                      |
| `aws_iam_policy_attachment`            | Attaches policy to the IAM user                               |
| `aws_iam_access_key`                   | Generates CLI/API access credentials for IAM user             |
| `aws_kms_key`                          | Used to encrypt secrets in AWS Secrets Manager & S3           |
| `aws_secretsmanager_secret`           | Securely stores the user's access key ID and secret           |
| `aws_s3_bucket`                        | Stores CloudTrail logs                                        |
| `aws_cloudtrail`                       | Enables auditing of AWS API calls                             |
| `aws_s3_bucket_policy`                 | Grants CloudTrail write access to the S3 bucket               |
| `aws_s3_bucket_server_side_encryption_configuration` | Encrypts logs using KMS            |

---

## Usage

terraform init

terraform plan
terraform apply

The access key and secret are securely stored in AWS Secrets Manager.

To retrieve them:

aws secretsmanager get-secret-value \
  --secret-id iam-user-readonly-ec2-user-credentials \
  --region ap-south-1


Requirements
Terraform v1.3 or higher
AWS CLI configured with appropriate IAM permissions


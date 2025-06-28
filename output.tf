output "iam_username" {
  value = aws_iam_user.new_user.name
}

output "cloudtrail_bucket" {
  value = aws_s3_bucket.cloudtrail_bucket.bucket
}

output "secret_arn" {
  value = aws_secretsmanager_secret.iam_user_secret.arn
}

output "iam_user_secret_name" {
  value     = aws_secretsmanager_secret.iam_user_secret.name
  sensitive = true
}
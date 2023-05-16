provider "aws" {
  region = var.region
}

resource "aws_dynamodb_table" "dynamodb_table" {
  name         = "jb-sw-realm-${lower(var.realm_id)}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "recordId"
  attribute {
    name = "recordId"
    type = "S"
  }
}

resource "aws_secretsmanager_secret" "tenant_secret" {
  for_each = var.tenant_secrets
  name     = "jb-sw-tenant-${each.key}"
}

resource "aws_secretsmanager_secret_version" "tenant_secret_version" {
  for_each       = var.tenant_secrets
  secret_id      = aws_secretsmanager_secret.tenant_secret[each.key].id
  secret_string  = each.value
  version_stages = ["1"]
}

resource "aws_iam_policy" "dynamodb_policy" {
  name = "jb-sw-realm-dynamodb-policy"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
        "Effect": "Allow",
        "Action": [
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:DeleteItem",
            "dynamodb:UpdateItem"
        ],
        "Resource": "${aws_dynamodb_table.dynamodb_table.arn}"
        }
    ]
}
    EOF
}

resource "aws_iam_policy" "secrets_manager_policy" {
  for_each = var.tenant_secrets
  name     = "jb-sw-realm-secrets-manager-policy-tenant-${each.key}"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
        "Effect": "Allow",
        "Action": [
            "secretsmanager:DescribeSecret",
            "secretsmanager:GetSecretValue"
        ],
        "Resource": "${aws_secretsmanager_secret.tenant_secret[each.key].arn}"
        }
    ]
}
    EOF
}

resource "aws_iam_role" "jb_sw_realm_role" {
  name               = "jb-sw-realm-role"
  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
        "Sid": "",
        "Effect": "Allow",
        "Principal": {
            "Service": "ec2.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
        }
    ]
}
    EOF
}

resource "aws_iam_instance_profile" "jb_sw_realm_instance_profile" {
  name = "jb-sw-realm-instance-profile"
  role = aws_iam_role.jb_sw_realm_role.name
}

resource "aws_iam_role_policy_attachment" "dynamodb_policy_attachment" {
  policy_arn = aws_iam_policy.dynamodb_policy.arn
  role       = aws_iam_role.jb_sw_realm_role.name
}

resource "aws_iam_role_policy_attachment" "secrets_manager_policy_attachment" {
  for_each   = var.tenant_secrets
  policy_arn = aws_iam_policy.secrets_manager_policy[each.key].arn
  role       = aws_iam_role.jb_sw_realm_role.name
}

resource "aws_iam_role_policy_attachment" "beanstalk_policy_attachment" {
  policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
  role       = aws_iam_role.jb_sw_realm_role.name
}

resource "aws_elastic_beanstalk_application" "jb_sw_realm" {
  name        = "jb-sw-realm"
  description = "Juicebox Software Realm"
}

resource "aws_elastic_beanstalk_environment" "jb_sw_realm" {
  name                   = "jb-sw-realm"
  application            = aws_elastic_beanstalk_application.jb_sw_realm.name
  solution_stack_name    = "64bit Amazon Linux 2 v3.7.2 running Go 1"
  tier                   = "WebServer"
  wait_for_ready_timeout = "20m"

  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "IamInstanceProfile"
    value     = aws_iam_instance_profile.jb_sw_realm_instance_profile.name
  }

  setting {
    namespace = "aws:elasticbeanstalk:application:environment"
    name      = "REALM_ID"
    value     = var.realm_id
  }

  setting {
    namespace = "aws:elasticbeanstalk:application:environment"
    name      = "PROVIDER"
    value     = "aws"
  }

  setting {
    namespace = "aws:elasticbeanstalk:application:environment"
    name      = "AWS_REGION_NAME"
    value     = var.region
  }

  setting {
    namespace = "aws:elasticbeanstalk:application:environment"
    name      = "PORT"
    value     = "5000"
  }

  depends_on = [
    aws_iam_role_policy_attachment.dynamodb_policy_attachment,
    aws_iam_role_policy_attachment.secrets_manager_policy_attachment,
    aws_iam_instance_profile.jb_sw_realm_instance_profile
  ]
}

resource "aws_cloudfront_distribution" "distribution" {
  origin {
    domain_name = aws_elastic_beanstalk_environment.jb_sw_realm.endpoint_url
    origin_id   = "jb-sw-realm-origin"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_ssl_protocols   = ["TLSv1.2"]
      origin_protocol_policy = "http-only"
    }
  }

  enabled         = true
  is_ipv6_enabled = true
  comment         = "Juicebox Software Realm Distribution"

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "PATCH", "PUT", "POST", "DELETE", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "jb-sw-realm-origin"
    viewer_protocol_policy = "https-only"

    forwarded_values {
      query_string = false
      headers      = ["*"]

      cookies {
        forward = "none"
      }
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
      locations        = []
    }
  }
}

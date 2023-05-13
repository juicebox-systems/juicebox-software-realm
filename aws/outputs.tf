output "CLOUDFRONT_DOMAIN" {
    value = "https://${aws_cloudfront_distribution.distribution.domain_name}"
}

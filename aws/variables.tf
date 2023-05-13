variable "realm_id" {
    description = "A UUID that identifies your realm"
    type        = string
}

variable "region" {
  description = "AWS Region"
  type        = string
  default     = "us-east-1"
}

variable "tenant_secrets" {
  description = "The names of any tenants you will be allowing access to (alphanumeric) mapped to their auth signing key. Read the 'Tenant Auth Secrets' section of the README for more details."
  type        = map(string)
}

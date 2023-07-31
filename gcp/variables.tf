variable "project_id" {
  description = "Google Cloud Project ID"
  type        = string
}

variable "realm_id" {
  description = "A 16-byte hex string that identifies your realm"
  type        = string
}

variable "region" {
  description = "Google Cloud Region"
  type        = string
  default     = "us-west2"
}

variable "zone" {
  description = "Google Cloud Zone"
  type        = string
  default     = "us-west2-a"
}

variable "tenant_secrets" {
  description = "The names of any tenants you will be allowing access to (alphanumeric) mapped to their auth signing key. Read the 'Tenant Auth Secrets' section of the README for more details."
  type        = map(string)
}

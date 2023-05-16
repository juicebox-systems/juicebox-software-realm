output "REALM_ID" {
  value = var.realm_id
}

output "BIGTABLE_INSTANCE_ID" {
  value = google_bigtable_instance.instance.name
}

output "GCP_PROJECT_ID" {
  value = var.project_id
}

output "SERVICE_ACCOUNT" {
  value = google_service_account.service_account.email
}

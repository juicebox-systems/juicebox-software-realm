# Configure the Google Cloud provider
provider "google" {
  project = var.project_id
  region  = var.region
}

# Enable required APIs
resource "google_project_service" "app_engine" {
  service = "appengine.googleapis.com"
}

resource "google_project_service" "secrets_manager" {
  project = var.project_id
  service = "secretmanager.googleapis.com"
}

resource "google_project_service" "pub_sub" {
  project = var.project_id
  service = "pubsub.googleapis.com"
}

# Create app engine service account
resource "google_service_account" "service_account" {
  account_id   = "jb-sw-realms"
  display_name = "Juicebox Software Realms"
}

# Create each tenant secret
resource "google_secret_manager_secret" "secret" {
  for_each  = var.tenant_secrets
  project   = var.project_id
  secret_id = "jb-sw-tenant-${each.key}"
  replication {
    automatic = true
  }
}

# Add the secret data for each tenant secret
resource "google_secret_manager_secret_version" "secret" {
  for_each    = var.tenant_secrets
  secret      = google_secret_manager_secret.secret[each.key].id
  secret_data = each.value
}

# Grant access to the app engine for each tenant secret
resource "google_secret_manager_secret_iam_binding" "access" {
  for_each  = var.tenant_secrets
  project   = var.project_id
  secret_id = google_secret_manager_secret.secret[each.key].id
  role      = "roles/secretmanager.secretAccessor"

  members = [
    "serviceAccount:${google_service_account.service_account.email}"
  ]
}

# Create Bigtable instance
resource "google_bigtable_instance" "instance" {
  project      = var.project_id
  name         = "jb-sw-realms"
  display_name = "Juicebox Software Realms"

  cluster {
    cluster_id = "jb-sw-realms-cluster"
    zone       = var.zone
    autoscaling_config {
      min_nodes  = 1
      max_nodes  = 5
      cpu_target = 80
    }
  }
}

# Grant access to the app engine for the Bigtable instance
resource "google_bigtable_instance_iam_binding" "access" {
  project  = var.project_id
  instance = google_bigtable_instance.instance.name
  role     = "roles/bigtable.admin"

  members = [
    "serviceAccount:${google_service_account.service_account.email}"
  ]
}

# Create App Engine application
resource "google_app_engine_application" "app" {
  project     = var.project_id
  location_id = var.region
}

# Grant log writer permissions to app engine
resource "google_project_iam_binding" "logs_writer_binding" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  members = [
    "serviceAccount:${google_service_account.service_account.email}"
  ]
}

# Grant object reader permissions to app engine so it can access Google Container Registry
resource "google_project_iam_binding" "storage_object_viewer_binding" {
  project = var.project_id
  role    = "roles/storage.objectViewer"
  members = [
    "serviceAccount:${google_service_account.service_account.email}"
  ]
}

# Define a custom role with the specific pub/sub perms needed.
resource "google_project_iam_custom_role" "pubsub_role" {
  project     = var.project_id
  role_id     = "pubsub_role"
  title       = "Role for managing pub/sub from a software realm"
  description = "Role for managing pub/sub from a software realm"
  permissions = ["pubsub.subscriptions.create",
    "pubsub.topics.attachSubscription",
    "pubsub.topics.create",
    "pubsub.topics.publish",
    "pubsub.subscriptions.consume",
  ]
}

# Grant pub/sub access to the service account
resource "google_project_iam_binding" "pubsub_binding" {
  project = var.project_id
  role    = google_project_iam_custom_role.pubsub_role.name
  members = [
    "serviceAccount:${google_service_account.service_account.email}"
  ]
}

terraform {
  required_providers {
    external = {
      source  = "hashicorp/external"
      version = "~> 2.3.1"
    }
    hcp = {
      source  = "hashicorp/hcp"
      version = "~> 0.66.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 3.18.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.4.0"
    }
    tfe = {
      source  = "hashicorp/tfe"
      version = "~> 0.47.0"
    }
  }
}

data "external" "env" {
  program = ["${path.module}/env.sh"]
}

provider "hcp" {
  project_id    = "2877dada-2716-4209-bfd8-1c2cbf168bc5"
  client_id     = data.external.env.result["client_id"]
  client_secret = data.external.env.result["client_secret"]
}

data "hcp_vault_cluster" "gs" {
  project_id = "2877dada-2716-4209-bfd8-1c2cbf168bc5"
  cluster_id = "hcp-najihun-vault"
}

//////////////////////////////
// Vault
//////////////////////////////
provider "vault" {
  address   = data.hcp_vault_cluster.gs.vault_public_endpoint_url
  namespace = "admin"
}

resource "vault_namespace" "ubuntu_2023" {
  path = "ubuntu-2023"
}

// Terraform Dynamic Provider Credentials
resource "vault_jwt_auth_backend" "tf" {
  namespace          = vault_namespace.ubuntu_2023.path
  description        = "Demonstration of the Terraform JWT auth backend"
  path               = "jwt"
  oidc_discovery_url = "https://app.terraform.io"
  bound_issuer       = "https://app.terraform.io"
}

resource "vault_policy" "tf" {
  namespace = vault_namespace.ubuntu_2023.path
  name      = "tfc-ubuntu2023-policy"

  policy = <<EOT
# Allow tokens to query themselves
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# Allow tokens to renew themselves
path "auth/token/renew-self" {
    capabilities = ["update"]
}

# Allow tokens to revoke themselves
path "auth/token/revoke-self" {
    capabilities = ["update"]
}

# Configure the actual secrets the token should have access to
path "kv/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "ssh/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOT
}

resource "vault_jwt_auth_backend_role" "example" {
  namespace      = vault_namespace.ubuntu_2023.path
  backend        = vault_jwt_auth_backend.tf.path
  role_name      = "tfc-role"
  token_policies = ["tfc-ubuntu2023-policy"]

  bound_audiences   = ["vault.workload.identity"]
  bound_claims_type = "glob"
  bound_claims = {
    sub = "organization:great-stone-biz:project:ubuntu-2023:workspace:*:run_phase:*"
  }
  user_claim = "terraform_full_workspace"
  role_type  = "jwt"
  token_ttl  = 20 * 60
}

// KV
resource "vault_mount" "kv_v2" {
  namespace = vault_namespace.ubuntu_2023.path
  path      = "kv"
  type      = "kv-v2"
}

// SSH
resource "vault_mount" "ssh" {
  namespace = vault_namespace.ubuntu_2023.path
  path      = "ssh"
  type      = "ssh"
}

// SSH OTP
resource "vault_ssh_secret_backend_role" "ubuntu_otp" {
  namespace     = vault_namespace.ubuntu_2023.path
  name          = "otp-role"
  backend       = vault_mount.ssh.path
  key_type      = "otp"
  default_user  = "ubuntu"
  allowed_users = "ubuntu"
  cidr_list     = "0.0.0.0/0"
}

// SSH CA
resource "vault_ssh_secret_backend_ca" "ubuntu_ca" {
  namespace            = vault_namespace.ubuntu_2023.path
  backend              = vault_mount.ssh.path
  generate_signing_key = true
}

resource "vault_ssh_secret_backend_role" "ubuntu_ca" {
  namespace               = vault_namespace.ubuntu_2023.path
  name                    = "ca-role"
  backend                 = vault_mount.ssh.path
  key_type                = "ca"
  default_user            = "ubuntu"
  allow_user_certificates = true
  allowed_user_key_config {
    type    = "rsa"
    lengths = [2048, 4096]
  }
  allowed_users      = "*"
  allowed_extensions = "permit-pty,permit-port-forwarding"
  default_extensions = {
    "permit-pty" : ""
  }
  ttl = 600 // 10m
}

//////////////////////////////
// SSH OTP Config
//////////////////////////////
resource "local_file" "helper_config" {
  content  = <<EOT
    vault_addr = "${data.hcp_vault_cluster.gs.vault_public_endpoint_url}"
    ssh_mount_point = "${vault_mount.ssh.path}"
    namespace = "${vault_namespace.ubuntu_2023.id}"
    allowed_roles = "${vault_ssh_secret_backend_role.ubuntu_otp.name}"
    allowed_cidr_list = "0.0.0.0/0"
  EOT
  filename = "${path.module}/../02.packer/ubuntu-otp/files/config.hcl"
}

//////////////////////////////
// SSH CA Config
//////////////////////////////
resource "local_file" "public_key" {
  content  = vault_ssh_secret_backend_ca.ubuntu_ca.public_key
  filename = "${path.module}/../02.packer/ubuntu-ca/files/trusted-user-ca-keys.pem"
}

//////////////////////////////
// TFC
//////////////////////////////
data "tfe_organization" "test-org" {
  name = "najihun"
}

resource "tfe_project" "project-sds" {
  organization = data.tfe_organization.test-org.name
  name         = "project-sds"
}

resource "tfe_workspace" "image_driven" {
  name         = "ubuntu-ssh"
  organization = data.tfe_organization.test-org.name
  project_id   = tfe_project.ubuntu_2023.id

  tag_names = [
    "ubuntu-ca",
    "image-driven",
  ]
}

resource "tfe_workspace" "ubuntu_ansible" {
  name         = "ubuntu-ansible-terraform"
  organization = data.tfe_organization.test-org.name
  project_id   = tfe_project.ubuntu_2023.id

  tag_names = [
    "2023-ubuntu",
    "ansible",
  ]
}

resource "tfe_variable_set" "hcp_vault" {
  name         = "HCP-Vault-Dynamic"
  description  = "HCP Vault Dynamic Privider Credentials"
  organization = data.tfe_organization.test-org.name
}

resource "tfe_project_variable_set" "ubuntu_2023" {
  project_id      = tfe_project.ubuntu_2023.id
  variable_set_id = tfe_variable_set.hcp_vault.id
}

locals {
  hcp_vault_dynamic = {
    TFC_VAULT_PROVIDER_AUTH = "true"
    TFC_VAULT_ADDR          = data.hcp_vault_cluster.gs.vault_public_endpoint_url
    TFC_VAULT_RUN_ROLE      = vault_jwt_auth_backend_role.example.role_name
    TFC_VAULT_NAMESPACE     = vault_namespace.ubuntu_2023.id
    TFC_VAULT_AUTH_PATH     = vault_jwt_auth_backend.tf.path
  }
}

resource "tfe_variable" "hcp_vault" {
  for_each        = local.hcp_vault_dynamic
  key             = each.key
  value           = each.value
  category        = "env"
  description     = each.key
  variable_set_id = tfe_variable_set.hcp_vault.id
}
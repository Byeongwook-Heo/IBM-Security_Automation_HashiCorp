job "portal" {
  datacenters = ["dc1"]
  type = "service"
  group "app" {
    task "portal" {
      driver = "docker"
      config { image = "${NOMAD_ENTERPRISE_IMAGE_URI}" command = "sh" args = ["-c", "echo portal placeholder && sleep 3600"] }
      vault { policies = ["portal-read"] }
      template { destination = "secrets/env" env = true data = <<EOH
ENTERPRISE_LICENSE_PATH=${NOMAD_META_ENTERPRISE_LICENSE_VAULT_PATH}
QRADAR_API_TOKEN={{ with secret "kv/data/qradar" }}{{ .Data.data.api_token }}{{ end }}
EOH
      }
    }
  }
}

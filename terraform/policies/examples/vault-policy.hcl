path "kv/data/apps/{{identity.entity.aliases.auth_oidc.name}}/*" { capabilities = ["read"] }
path "database/creds/dba-readwrite" { capabilities = ["read"] }
path "sys/audit" { capabilities = ["read", "sudo"] }

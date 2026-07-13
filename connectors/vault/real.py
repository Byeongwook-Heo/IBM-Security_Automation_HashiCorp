from typing import Any

from connectors.common import ConnectorConfig, HttpApiConnector


class RealVaultConnector(HttpApiConnector):
    def __init__(self):
        super().__init__(
            ConnectorConfig.from_env(
                "VAULT",
                "vault",
                "/v1/sys/health",
                base_envs=("VAULT_BASE_URL", "VAULT_ADDR"),
                token_envs=("VAULT_API_TOKEN", "VAULT_TOKEN"),
                token_header="X-Vault-Token",
                token_prefix="",
            )
        )

    def normalize(self, record: Any) -> dict[str, Any]:
        event = super().normalize(record)
        event["event_type"] = "vault_health"
        if isinstance(record, dict):
            sealed = bool(record.get("sealed"))
            event["severity"] = "critical" if sealed else "info"
            event["risk_score"] = 95 if sealed else 10
        return event

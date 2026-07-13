from connectors.common import ConnectorConfig, HttpApiConnector


class RealGuardiumConnector(HttpApiConnector):
    def __init__(self):
        super().__init__(
            ConnectorConfig.from_env(
                "GUARDIUM",
                "guardium",
                "/api/v3/reports",
                base_envs=("GUARDIUM_BASE_URL", "GUARDIUM_API_URL"),
                token_envs=("GUARDIUM_API_TOKEN", "GUARDIUM_TOKEN"),
            )
        )

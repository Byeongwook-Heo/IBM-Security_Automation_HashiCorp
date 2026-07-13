from connectors.common import ConnectorConfig, HttpApiConnector


class RealTurbonomicConnector(HttpApiConnector):
    def __init__(self):
        super().__init__(
            ConnectorConfig.from_env(
                "TURBONOMIC",
                "turbonomic",
                "/api/v3/search?types=Action",
                base_envs=("TURBONOMIC_BASE_URL", "TURBONOMIC_API_URL"),
                token_envs=("TURBONOMIC_API_TOKEN", "TURBONOMIC_TOKEN"),
            )
        )

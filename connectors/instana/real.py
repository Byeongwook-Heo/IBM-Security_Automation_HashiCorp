from connectors.common import ConnectorConfig, HttpApiConnector


class RealInstanaConnector(HttpApiConnector):
    def __init__(self):
        super().__init__(
            ConnectorConfig.from_env(
                "INSTANA",
                "instana",
                "/api/events",
                base_envs=("INSTANA_BASE_URL", "INSTANA_API_URL"),
                token_envs=("INSTANA_API_TOKEN", "INSTANA_TOKEN"),
                token_prefix="apiToken",
            )
        )

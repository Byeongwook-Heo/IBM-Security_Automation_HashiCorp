from connectors.common import ConnectorConfig, HttpApiConnector


class RealBoundaryConnector(HttpApiConnector):
    def __init__(self):
        super().__init__(
            ConnectorConfig.from_env(
                "BOUNDARY",
                "boundary",
                "/v1/sessions",
                base_envs=("BOUNDARY_BASE_URL", "BOUNDARY_ADDR"),
                token_envs=("BOUNDARY_API_TOKEN", "BOUNDARY_TOKEN"),
            )
        )

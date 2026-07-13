from connectors.common import ConnectorConfig, HttpApiConnector


class RealVerifyConnector(HttpApiConnector):
    def __init__(self):
        super().__init__(
            ConnectorConfig.from_env(
                "VERIFY",
                "verify",
                "/v1.0/diagnostics/events",
                base_envs=("VERIFY_BASE_URL", "VERIFY_API_URL", "IBM_VERIFY_ISSUER_URL"),
                token_envs=("VERIFY_API_TOKEN", "VERIFY_TOKEN", "IBM_VERIFY_ACCESS_TOKEN"),
            )
        )

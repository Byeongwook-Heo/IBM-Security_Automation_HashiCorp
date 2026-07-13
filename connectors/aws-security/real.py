from connectors.common import ConnectorConfig, HttpApiConnector


class RealAwsSecurityConnector(HttpApiConnector):
    def __init__(self):
        super().__init__(
            ConnectorConfig.from_env(
                "AWS_SECURITY",
                "aws-security",
                "/securityhub/findings",
                base_envs=("AWS_SECURITY_BASE_URL", "AWS_SECURITY_API_URL"),
                token_envs=("AWS_SECURITY_API_TOKEN", "AWS_SECURITY_TOKEN"),
            )
        )

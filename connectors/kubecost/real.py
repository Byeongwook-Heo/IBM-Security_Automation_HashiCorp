from connectors.common import ConnectorConfig, HttpApiConnector


class RealKubecostConnector(HttpApiConnector):
    def __init__(self):
        super().__init__(
            ConnectorConfig.from_env(
                "KUBECOST",
                "kubecost",
                "/model/allocation?window=1d&aggregate=namespace",
                base_envs=("KUBECOST_BASE_URL", "KUBECOST_API_URL"),
                token_envs=("KUBECOST_API_TOKEN", "KUBECOST_TOKEN"),
            )
        )

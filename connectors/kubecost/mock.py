class MockKubecostConnector:
    def collect(self):
        return [{"source_product":"kubecost","event_type":"mock_event","severity":"info","risk_score":10,"deep_link":"https://example.invalid/kubecost"}]

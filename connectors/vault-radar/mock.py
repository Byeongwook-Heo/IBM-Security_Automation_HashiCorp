class MockVaultRadarConnector:
    def collect(self):
        return [{"source_product":"vault-radar","event_type":"mock_event","severity":"info","risk_score":10,"deep_link":"https://example.invalid/vault-radar"}]

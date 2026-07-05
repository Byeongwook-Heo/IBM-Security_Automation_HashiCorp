from .models import CommonEvent, Entity

class MockRepository:
    def __init__(self):
        self.audit_events: list[CommonEvent] = []
        self.offenses = [{"id":"off-1001","name":"Abnormal PII access after privileged session","severity":"critical","status":"open","risk_score":96,"deep_link":"https://qradar.example/offenses/1001"}]
        self.findings = [{"id":"vr-1","source":"Vault Radar","type":"secret_exposure","severity":"critical","secret_path":"repo/terraform/main.tf","risk_score":95,"deep_link":"https://vault-radar.example/findings/vr-1"}]
        self.assets = [Entity(id="db-1", name="customer-aurora", type="database", risk_score=88, deep_link="https://guardium.example/assets/db-1")]
        self.apps = [Entity(id="app-1", name="payments-api", type="application", risk_score=72, deep_link="https://concert.example/apps/app-1")]
        self.data_assets = [{"id":"pii-1","database":"customer-aurora","table":"customers.pii","classification":"restricted","risk_score":91}]
        self.users = [{"id":"u-1","email":"analyst@example.com","groups":["SOC_ADMIN","SECURITY_ANALYST"]}]
        self.sessions = [{"id":"sess-1","user_email":"dba@example.com","target":"customer-aurora","status":"active","deep_link":"https://boundary.example/sessions/sess-1"}]
        self.secrets = [{"id":"sec-1","path":"database/creds/customer-readwrite","status":"issued","risk_score":70}]
        self.kubecost = [{"namespace":"payments","team":"app","daily_cost":420.50,"anomaly":True}]
        self.turbo = [{"id":"turbo-1","action":"rightsize deployment payments-api","state":"pending_approval","savings":123.45}]
        self.concert = [{"app_id":"app-1","risk_score":82,"drivers":["latency","certificate_expiring","secret_exposure"]}]
    def summary(self):
        return {"security_score":64,"open_offenses":len(self.offenses),"critical_findings":1,"exposed_secrets":1,"data_risk":91,"app_risk":82,"cost_risk":76,"pending_approvals":1}
    def timeline(self, case_id: str):
        return [
            {"time":"2026-07-04T00:00:00Z","source":"Verify","event":"MFA failures","case_id":case_id},
            {"time":"2026-07-04T00:03:00Z","source":"Boundary","event":"Privileged session started","case_id":case_id},
            {"time":"2026-07-04T00:04:00Z","source":"Vault","event":"Dynamic DB credential issued","case_id":case_id},
            {"time":"2026-07-04T00:06:00Z","source":"Guardium","event":"PII table mass SELECT","case_id":case_id},
            {"time":"2026-07-04T00:07:00Z","source":"QRadar","event":"Offense created","case_id":case_id},
        ]
repo = MockRepository()

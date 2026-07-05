from fastapi.testclient import TestClient
from app.main import app
client = TestClient(app)
def test_health(): assert client.get('/health').json()['status'] == 'ok'
def test_summary(): assert 'open_offenses' in client.get('/api/dashboard/summary').json()
def test_mutation_audit():
    r = client.post('/api/workflows/cases', json={'target_id':'x','reason':'test','dry_run':True})
    assert r.status_code == 200
    assert client.get('/api/audit/events').json()

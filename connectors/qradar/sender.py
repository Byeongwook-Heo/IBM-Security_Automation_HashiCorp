import json, socket

def json_syslog(event): return '<134> '+json.dumps(event, default=str)
def leef(event): return f"LEEF:2.0|Lab|Connector|0.1|{event.get('event_type','event')}|sev={event.get('severity','info')}	risk_score={event.get('risk_score',0)}"
def send(event, host=None, port=514, dry_run=True):
    payload=json_syslog(event)
    if dry_run or not host: return {"dry_run": True, "payload": payload, "leef": leef(event)}
    with socket.create_connection((host,port), timeout=5) as s: s.sendall(payload.encode())
    return {"dry_run": False}

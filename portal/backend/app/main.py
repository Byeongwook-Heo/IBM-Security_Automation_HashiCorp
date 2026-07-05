from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from .auth import current_user, require_role
from .models import CommonEvent, WorkflowRequest
from .repository import repo
from .qradar_sender import send_event
from .enterprise import enterprise_status

app = FastAPI(title="Information Security Portal")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.middleware("http")
async def audit_mutations(request: Request, call_next):
    response = await call_next(request)
    if request.method in {"POST","PUT","PATCH","DELETE"}:
        repo.audit_events.append(CommonEvent(source_product="SecurityPortal", event_type="portal_mutation", severity="info", action=f"{request.method} {request.url.path}", result=str(response.status_code)))
    return response

@app.get("/health")
def health(): return {"status":"ok","mode":"mock"}
@app.get("/api/dashboard/summary")
def summary(): return repo.summary()
@app.get("/api/soc/offenses")
def offenses(): return repo.offenses
@app.get("/api/soc/timeline/{case_id}")
def timeline(case_id: str): return repo.timeline(case_id)
@app.get("/api/findings")
def findings(): return repo.findings
@app.get("/api/assets")
def assets(): return repo.assets
@app.get("/api/apps")
def apps(): return repo.apps
@app.get("/api/data-assets")
def data_assets(): return repo.data_assets
@app.get("/api/identity/users")
def users(): return repo.users
@app.get("/api/access/sessions")
def sessions(): return repo.sessions
@app.get("/api/secrets")
def secrets(): return repo.secrets
@app.get("/api/cost/kubecost")
def kubecost(): return repo.kubecost
@app.get("/api/optimization/turbonomic")
def turbo(): return repo.turbo
@app.get("/api/concert/risks")
def concert(): return repo.concert
@app.get("/api/audit/events")
def audit_events(): return repo.audit_events
@app.get("/api/enterprise/status")
def enterprise(): return enterprise_status()
@app.post("/api/workflows/cases")
def create_case(req: WorkflowRequest, user=Depends(current_user)):
    require_role(user,["SOC_ADMIN","SECURITY_ANALYST"]); return {"case_id":"case-demo-1","status":"created","dry_run":req.dry_run}
@app.post("/api/workflows/actions/revoke-credential")
def revoke(req: WorkflowRequest, user=Depends(current_user)): return {"status":"placeholder","action":"revoke_credential","dry_run":req.dry_run}
@app.post("/api/workflows/actions/terminate-session")
def terminate(req: WorkflowRequest, user=Depends(current_user)): return {"status":"placeholder","action":"terminate_session","dry_run":req.dry_run}
@app.post("/api/workflows/actions/approve-turbonomic-action")
def approve(req: WorkflowRequest, user=Depends(current_user)): return {"status":"approval_recorded","auto_execute":False,"dry_run":req.dry_run}
@app.post("/api/workflows/actions/send-qradar-event")
def qradar(req: WorkflowRequest): return send_event(CommonEvent(source_product="SecurityPortal", event_type="workflow_event", severity="medium", action="send_qradar_event", risk_score=50), dry_run=req.dry_run)
@app.post("/api/workflows/actions/trigger-terraform-run")
def tf(req: WorkflowRequest): return {"status":"placeholder","action":"trigger_terraform_run","human_review_required":True,"dry_run":req.dry_run}

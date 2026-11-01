import os
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from common.oidc import mount_auth, stamp

APPLICATION = "northstar-finance"
REPORTS: list[dict] = [
    {"id": "R-100", "title": "October close", "status": "approved", "author": "elena.vasquez"},
    {"id": "R-101", "title": "Deferred revenue", "status": "draft", "author": "benicio.alves"},
]

app = FastAPI(title="Northstar Finance")
require = None


def config() -> dict:
    public_issuer = os.environ["KEYCLOAK_PUBLIC_URL"].rstrip("/") + "/realms/" + os.environ.get("KEYCLOAK_REALM", "northstar")
    internal = os.environ["KEYCLOAK_INTERNAL_URL"].rstrip("/") + "/realms/" + os.environ.get("KEYCLOAK_REALM", "northstar")
    return {
        "application": APPLICATION,
        "client_id": os.environ["OIDC_CLIENT_ID"],
        "client_secret": os.environ["OIDC_CLIENT_SECRET"],
        "public": os.environ["PUBLIC_APP_URL"].rstrip("/"),
        "public_issuer": public_issuer,
        "issuer": public_issuer,
        "internal": internal,
        "secret": os.environ.get("SESSION_SECRET", "finance-session"),
        "cookie": "finance_session",
    }


mount_auth(app, config())


def guard(action: str, fresh: bool = False):
    return app.state.require(action, fresh=fresh)


@app.get("/health")
def health():
    return {"status": "ok", "application": "northstar-finance"}


@app.get("/", response_class=HTMLResponse)
def home():
    return """<!doctype html><html><head><title>Northstar Finance</title>
    <style>body{font-family:Segoe UI,sans-serif;margin:2rem;color:#17202a;background:#f4f7fb} table{border-collapse:collapse} td,th{border-bottom:1px solid #d5dde8;padding:.4rem .8rem;text-align:left} button{margin-right:.4rem}</style></head>
    <body><h1>Northstar Finance</h1><p id="who">Checking session…</p><div id="app"></div>
    <script>
    async function load(){
      const session = await fetch('/auth/session');
      const who = document.getElementById('who');
      if(!session.ok){ who.innerHTML = '<a href="/auth/login">Sign in with Northstar</a>'; return; }
      const me = await session.json();
      who.textContent = me.username + ' · ' + me.roles.join(', ');
      const reports = await fetch('/api/reports');
      const rows = reports.ok ? await reports.json() : [];
      document.getElementById('app').innerHTML = `<table><tr><th>Report</th><th>Status</th><th>Author</th></tr>${rows.map(r=>`<tr><td>${r.title}</td><td>${r.status}</td><td>${r.author}</td></tr>`).join('')}</table>
        <p><button id="create">Create report</button><button id="approve">Approve R-101</button><button id="settings">Change settings</button><button id="out">Sign out</button></p><pre id="result"></pre>`;
      const call = async (url, options) => { const response = await fetch(url, options); document.getElementById('result').textContent = response.status + ' ' + await response.text(); if(response.ok) load(); };
      document.getElementById('create').onclick = () => call('/api/reports', {method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':me.csrf}, body: JSON.stringify({title:'Adjustment '+Date.now()})});
      document.getElementById('approve').onclick = () => call('/api/reports/R-101/approve', {method:'POST', headers:{'X-CSRF-Token':me.csrf}});
      document.getElementById('settings').onclick = () => call('/api/settings', {method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':me.csrf}, body:'{}'});
      document.getElementById('out').onclick = async () => { const response = await fetch('/auth/logout', {method:'POST', headers:{'X-CSRF-Token':me.csrf}}); const body = await response.json(); location = body.logout_url; };
    }
    load();
    </script></body></html>"""


def csrf(request_headers, session) -> None:
    if request_headers.get("x-csrf-token") != session["csrf"]:
        raise HTTPException(status_code=403, detail="CSRF token is missing or invalid.")


@app.get("/api/reports")
def reports(session: dict = Depends(guard("report:read"))):
    return REPORTS


@app.post("/api/reports")
async def create_report(request: Request, session: dict = Depends(guard("report:create"))):
    csrf(request.headers, session)
    payload = await request.json()
    row = {"id": "R-" + uuid4().hex[:6], "title": payload.get("title") or "Untitled", "status": "draft", "author": session["username"], "created_at": stamp()}
    REPORTS.append(row)
    return row


@app.post("/api/reports/{report_id}/approve")
def approve(report_id: str, request: Request, session: dict = Depends(guard("payment:approve", fresh=True))):
    csrf(request.headers, session)
    for row in REPORTS:
        if row["id"] == report_id:
            row["status"] = "approved"
            row["approved_by"] = session["username"]
            row["approved_at"] = stamp()
            return row
    raise HTTPException(status_code=404, detail="Report was not found.")


@app.post("/api/settings")
async def settings(request: Request, session: dict = Depends(guard("app:configure"))):
    csrf(request.headers, session)
    return {"updated": True, "by": session["username"], "at": stamp()}

import os
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from common.oidc import mount_auth, stamp

APPLICATION = "northstar-projects"
PROJECTS = [
    {"id": "P-14", "name": "Billing integration", "status": "active"},
    {"id": "P-22", "name": "Directory cutover", "status": "planned"},
]

app = FastAPI(title="Northstar Projects")


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
        "secret": os.environ.get("SESSION_SECRET", "projects-session"),
        "cookie": "projects_session",
    }


mount_auth(app, config())


def guard(action: str, fresh: bool = False):
    return app.state.require(action, fresh=fresh)


def csrf(headers, session) -> None:
    if headers.get("x-csrf-token") != session["csrf"]:
        raise HTTPException(status_code=403, detail="CSRF token is missing or invalid.")


@app.get("/health")
def health():
    return {"status": "ok", "application": "northstar-projects"}


@app.get("/", response_class=HTMLResponse)
def home():
    return """<!doctype html><html><head><title>Northstar Projects</title>
    <style>body{font-family:Segoe UI,sans-serif;margin:2rem;color:#17202a;background:#f6f4ef} td,th{border-bottom:1px solid #ddd;padding:.4rem .8rem;text-align:left}</style></head>
    <body><h1>Northstar Projects</h1><p id="who">Checking session…</p><div id="app"></div>
    <script>
    async function load(){
      const session = await fetch('/auth/session');
      if(!session.ok){ document.getElementById('who').innerHTML = '<a href="/auth/login">Sign in with Northstar</a>'; return; }
      const me = await session.json();
      document.getElementById('who').textContent = me.username + ' · ' + me.roles.join(', ');
      const projects = await (await fetch('/api/projects')).json();
      document.getElementById('app').innerHTML = `<table><tr><th>Project</th><th>Status</th></tr>${projects.map(p=>`<tr><td>${p.name}</td><td>${p.status}</td></tr>`).join('')}</table>
        <p><button id="write">Update billing integration</button><button id="manage">Create project</button><button id="out">Sign out</button></p><pre id="result"></pre>`;
      const call = async (url, body) => { const response = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':me.csrf}, body: JSON.stringify(body||{})}); document.getElementById('result').textContent = response.status + ' ' + await response.text(); };
      document.getElementById('write').onclick = () => call('/api/projects/P-14', {status:'active'});
      document.getElementById('manage').onclick = () => call('/api/projects', {name:'New workspace'});
      document.getElementById('out').onclick = async () => { const response = await fetch('/auth/logout', {method:'POST', headers:{'X-CSRF-Token':me.csrf}}); location = (await response.json()).logout_url; };
    }
    load();
    </script></body></html>"""


@app.get("/api/projects")
def projects(session: dict = Depends(guard("project:read"))):
    return PROJECTS


@app.post("/api/projects/{project_id}")
async def update_project(project_id: str, request: Request, session: dict = Depends(guard("project:write"))):
    csrf(request.headers, session)
    payload = await request.json()
    for row in PROJECTS:
        if row["id"] == project_id:
            row["status"] = payload.get("status", row["status"])
            row["updated_by"] = session["username"]
            row["updated_at"] = stamp()
            return row
    raise HTTPException(status_code=404, detail="Project was not found.")


@app.post("/api/projects")
async def create_project(request: Request, session: dict = Depends(guard("project:manage", fresh=True))):
    csrf(request.headers, session)
    payload = await request.json()
    row = {"id": "P-" + uuid4().hex[:4], "name": payload.get("name") or "Untitled", "status": "planned", "owner": session["username"]}
    PROJECTS.append(row)
    return row

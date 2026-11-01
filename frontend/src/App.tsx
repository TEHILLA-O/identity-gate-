import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { ApiError, api, setCsrf, type Me, type Status } from "./api";
import { WORKSPACES, useUi } from "./store";
import { WorkspaceView } from "./workspaces";

export function App() {
  const me = useQuery({
    queryKey: ["me"],
    queryFn: async () => {
      const row = await api<Me>("/auth/me");
      setCsrf(row.csrf_token);
      return row;
    },
    retry: false,
  });
  if (me.isLoading) return <p className="canvas">Checking the Northstar session…</p>;
  if (me.error instanceof ApiError && me.error.status === 401) return <Gate />;
  if (!me.data) return <p className="error canvas">{String(me.error)}</p>;
  return <Shell me={me.data} />;
}

function Gate() {
  return (
    <main className="gate">
      <section className="gate-copy">
        <div className="brand"><span className="mark" /> IdentityGate</div>
        <p className="env">Northstar Digital · local demonstration</p>
        <h1>Who has access, how they got it, and whether it still holds.</h1>
        <p className="muted">Sign in through Keycloak. IdentityGate keeps governance state. Keycloak remains the authority for authentication.</p>
        <p><a className="primary" href="/api/v1/auth/login">Sign in with Northstar</a></p>
      </section>
      <section className="gate-map" />
    </main>
  );
}

function Shell({ me }: { me: Me }) {
  const workspace = useUi((state) => state.workspace);
  const setWorkspace = useUi((state) => state.setWorkspace);
  const inspector = useUi((state) => state.inspector);
  const inspect = useUi((state) => state.inspect);
  const density = useUi((state) => state.density);
  const toggleDensity = useUi((state) => state.toggleDensity);
  const palette = useUi((state) => state.palette);
  const setPalette = useUi((state) => state.setPalette);
  const status = useQuery({ queryKey: ["status"], queryFn: () => api<Status>("/system/status") });
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPalette(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setPalette]);
  return (
    <div className={`app ${density ? "dense" : ""}`}>
      <header className="ribbon">
        <div className="brand"><span className="mark" /> IdentityGate</div>
        <span className="env">{status.data?.environment ?? "local"} · {status.data?.organisation ?? "Northstar Digital"}</span>
        <button className="search" onClick={() => setPalette(true)}>Search identities and commands <span className="mono">Ctrl K</span></button>
        <span className={status.data?.keycloak ? "chip live" : "chip bad"}>{status.data?.keycloak ? "Keycloak connected" : "Keycloak unavailable"}</span>
        <span className={(status.data?.open_findings ?? 0) > 0 ? "chip warn" : "chip"}>{status.data?.open_findings ?? "—"} findings</span>
        <button className="chip" onClick={toggleDensity}>{density ? "Comfortable" : "Dense"}</button>
        <button className="chip" onClick={async () => { const body = await api<{ logout_url: string }>("/auth/logout", { method: "POST" }); window.location.href = body.logout_url; }}>{me.username}</button>
      </header>
      <nav className="rail">
        {WORKSPACES.map(([id, label]) => (
          <button key={id} className={workspace === id ? "active" : ""} onClick={() => setWorkspace(id)}>{label}</button>
        ))}
      </nav>
      <div className={inspector ? "stage" : "stage solo"}>
        <main className="canvas">
          <WorkspaceView me={me} name={workspace} />
        </main>
        {inspector ? (
          <aside className="inspector">
            <div className="actions"><h2>{inspector.title}</h2><button onClick={() => inspect(null)}>Dismiss</button></div>
            <pre className="mono">{JSON.stringify(inspector.body, null, 2)}</pre>
          </aside>
        ) : null}
      </div>
      {palette ? <Palette onClose={() => setPalette(false)} /> : null}
    </div>
  );
}

function Palette({ onClose }: { onClose: () => void }) {
  const [q, setQ] = useState("");
  const setWorkspace = useUi((state) => state.setWorkspace);
  const setFocus = useUi((state) => state.setFocus);
  const inspect = useUi((state) => state.inspect);
  const results = useQuery({
    queryKey: ["search", q],
    queryFn: () => api<{ identities: { username: string; label: string }[] }>(`/search?q=${encodeURIComponent(q)}`),
    enabled: q.trim().length > 1,
  });
  const commands = WORKSPACES.filter(([, label]) => label.toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="palette" onClick={onClose}>
      <form onClick={(event) => event.stopPropagation()} onSubmit={(event) => event.preventDefault()}>
        <input autoFocus value={q} placeholder="Find an identity, role, or workspace" onChange={(event) => setQ(event.target.value)} />
        {commands.map(([id, label]) => (
          <button key={id} onClick={() => { setWorkspace(id); onClose(); }}>{label}</button>
        ))}
        {(results.data?.identities ?? []).map((person) => (
          <button key={person.username} onClick={async () => {
            setFocus(person.username);
            inspect({ title: person.label, body: await api(`/identities/${person.username}`) });
            onClose();
          }}>{person.label}</button>
        ))}
      </form>
    </div>
  );
}

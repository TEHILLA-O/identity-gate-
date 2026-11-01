import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, can, type Me } from "./api";
import { IdentityGraph } from "./graph";
import { useUi, type Workspace } from "./store";

type Row = Record<string, unknown>;

export function WorkspaceView({ me, name }: { me: Me; name: Workspace }) {
  if (name === "overview") return <Overview />;
  if (name === "graph") return <GraphStudio />;
  if (name === "directory") return <Directory />;
  if (name === "lifecycle") return <Lifecycle me={me} />;
  if (name === "provisioning") return <Provisioning me={me} />;
  if (name === "reviews") return <Reviews me={me} />;
  if (name === "policies") return <Policies />;
  if (name === "security") return <Security me={me} />;
  if (name === "audit") return <Audit me={me} />;
  return <Reports me={me} />;
}

function Overview() {
  const status = useQuery({ queryKey: ["status"], queryFn: () => api<Row>("/system/status") });
  const findings = useQuery({ queryKey: ["findings"], queryFn: () => api<{ items: Row[] }>("/findings") });
  const events = useQuery({ queryKey: ["audit", "overview"], queryFn: () => api<{ items: Row[] }>("/audit-events?page_size=8") });
  const graph = useQuery({ queryKey: ["graph", ""], queryFn: () => api<{ nodes: never[]; edges: never[] }>("/graph") });
  const inspect = useUi((state) => state.inspect);
  const counts = countFindings(findings.data?.items ?? []);
  return (
    <>
      <div className="kpis">
        <Metric label="Identities" value={status.data?.identities} />
        <Metric label="Keycloak" value={status.data?.keycloak ? "connected" : "unavailable"} />
        <Metric label="Directory" value={status.data?.downstream ? "connected" : "unavailable"} />
        <Metric label="Open reviews" value={status.data?.open_reviews} />
        <Metric label="Open findings" value={status.data?.open_findings} />
        <Metric label="Policy" value={status.data?.policy_version} />
      </div>
      <div className="grid-2">
        <div>
          {graph.data ? <IdentityGraph graph={graph.data} /> : <p className="muted">Loading relationship map…</p>}
        </div>
        <div className="card">
          <h2>Attention</h2>
          <div style={{ height: 180 }}>
            <ResponsiveContainer>
              <BarChart data={counts}>
                <XAxis dataKey="name" stroke="#93a0b3" fontSize={12} />
                <YAxis stroke="#93a0b3" allowDecimals={false} width={28} />
                <Tooltip />
                <Bar dataKey="value" fill="#7c8cff" radius={4} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="timeline">
            {(findings.data?.items ?? []).slice(0, 6).map((item) => (
              <button className="chip" key={String(item.id)} onClick={() => inspect({ title: String(item.title), body: item })}>
                {String(item.severity)} · {String(item.title)}
              </button>
            ))}
          </div>
        </div>
      </div>
      <div className="card" style={{ marginTop: 12 }}>
        <h2>Operational timeline</h2>
        {(events.data?.items ?? []).map((event) => (
          <div className="event" key={String(event.id)}>
            <span className="mono">{String(event.occurred_at)}</span>
            <span>{String(event.type)} · {String(event.actor)} → {String(event.target)}</span>
            <span className={String(event.outcome) === "success" ? "ok" : "warn"}>{String(event.outcome)}</span>
          </div>
        ))}
      </div>
    </>
  );
}

function GraphStudio() {
  const focus = useUi((state) => state.focus);
  const setFocus = useUi((state) => state.setFocus);
  const graph = useQuery({ queryKey: ["graph", focus], queryFn: () => api<{ nodes: never[]; edges: never[] }>(`/graph?username=${encodeURIComponent(focus)}`) });
  const left = useField("elena.vasquez");
  const right = useField("marcus.hale");
  const compare = useQuery({
    queryKey: ["compare", left.value, right.value],
    queryFn: () => api<Row>(`/access-paths/compare?left=${left.value}&right=${right.value}`),
    enabled: false,
  });
  return (
    <>
      <div className="filters">
        <input value={focus} placeholder="Focus an identity, for example elena.vasquez" onChange={(event) => setFocus(event.target.value)} />
        <input {...left.bind} placeholder="Compare left" />
        <input {...right.bind} placeholder="Compare right" />
        <button className="primary" onClick={() => compare.refetch()}>Compare access</button>
      </div>
      {graph.data ? <IdentityGraph graph={graph.data} /> : null}
      {compare.data ? <pre className="card mono">{JSON.stringify(compare.data, null, 2)}</pre> : null}
    </>
  );
}

function Directory() {
  const q = useField("");
  const department = useField("");
  const people = useQuery({
    queryKey: ["identities", q.value, department.value],
    queryFn: () => api<{ items: Row[]; total: number }>(`/identities?q=${encodeURIComponent(q.value)}&department=${encodeURIComponent(department.value)}&page_size=50`),
  });
  const inspect = useUi((state) => state.inspect);
  const setFocus = useUi((state) => state.setFocus);
  return (
    <>
      <div className="filters">
        <input {...q.bind} placeholder="Search name, email, or employee number" />
        <select {...department.bind}>
          <option value="">All departments</option>
          {["Engineering", "Finance", "Sales", "Human Resources", "Operations", "Security"].map((item) => <option key={item}>{item}</option>)}
        </select>
        <span className="muted">{people.data?.total ?? 0} identities</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Employee</th><th>Department</th><th>Status</th><th>Account</th><th>Manager</th></tr></thead>
          <tbody>
            {(people.data?.items ?? []).map((person) => (
              <tr className="clickable" key={String(person.username)} onClick={async () => {
                const detail = await api<Row>(`/identities/${person.username}`);
                inspect({ title: String(person.name), body: detail });
              }}>
                <td><strong>{String(person.name)}</strong><div className="mono muted">{String(person.employee_number)} · {String(person.username)}</div></td>
                <td>{String(person.department)}<div className="muted">{String(person.title)}</div></td>
                <td>{String(person.employment_status)}</td>
                <td className="mono">{String(person.account_state)}</td>
                <td>
                  {String(person.manager ?? "—")}
                  <div><button className="chip" onClick={(event) => { event.stopPropagation(); setFocus(String(person.username)); }}>Open graph</button></div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function Lifecycle({ me }: { me: Me }) {
  const rows = useQuery({ queryKey: ["lifecycle"], queryFn: () => api<{ items: Row[] }>("/lifecycle") });
  const client = useQueryClient();
  const inspect = useUi((state) => state.inspect);
  const run = useMutation({
    mutationFn: (payload: { path: string; body: Row }) => api<Row>(payload.path, { method: "POST", body: JSON.stringify(payload.body) }),
    onSuccess: (data) => {
      inspect({ title: "Workflow", body: data });
      client.invalidateQueries({ queryKey: ["lifecycle"] });
    },
  });
  const number = useField("");
  const department = useField("Engineering");
  return (
    <>
      {can(me, "lifecycle:run") ? (
        <div className="card">
          <h2>Run a lifecycle change</h2>
          <div className="filters">
            <input {...number.bind} placeholder="Employee number, for example NS-10008" />
            <select {...department.bind}>{["Engineering", "Finance", "Sales", "Human Resources", "Operations", "Security"].map((item) => <option key={item}>{item}</option>)}</select>
          </div>
          <div className="actions">
            <button onClick={() => run.mutate({ path: "/lifecycle/movers", body: { employee_number: number.value, department: department.value } })}>Move department</button>
            <button className="danger" onClick={() => run.mutate({ path: "/lifecycle/leavers", body: { employee_number: number.value } })}>Start leaver</button>
            <button onClick={() => api("/system/expire", { method: "POST" }).then((body) => inspect({ title: "Expiry sweep", body }))}>Run expiry sweep</button>
          </div>
          {run.error ? <p className="error">{String(run.error.message)}</p> : null}
        </div>
      ) : <p className="muted">This account can review workflows. Lifecycle changes require an operator role.</p>}
      <div className="table-wrap">
        <table>
          <thead><tr><th>When</th><th>Type</th><th>Employee</th><th>Status</th><th></th></tr></thead>
          <tbody>
            {(rows.data?.items ?? []).map((row) => (
              <tr className="clickable" key={String(row.id)} onClick={() => inspect({ title: `${row.type} ${row.employee_number}`, body: row })}>
                <td className="mono">{String(row.created_at)}</td>
                <td>{String(row.type)}</td>
                <td className="mono">{String(row.employee_number)}</td>
                <td className={String(row.status) === "succeeded" ? "ok" : "warn"}>{String(row.status)}</td>
                <td>{can(me, "lifecycle:run") && row.status !== "succeeded" ? <button onClick={(event) => { event.stopPropagation(); api(`/lifecycle/${row.id}/retry`, { method: "POST" }).then(() => client.invalidateQueries({ queryKey: ["lifecycle"] })); }}>Retry failed stages</button> : null}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function Provisioning({ me }: { me: Me }) {
  const attempts = useQuery({ queryKey: ["attempts"], queryFn: () => api<{ items: Row[] }>("/provisioning/attempts") });
  const runs = useQuery({ queryKey: ["reconcile"], queryFn: () => api<{ items: Row[] }>("/provisioning/reconcile") });
  const inspect = useUi((state) => state.inspect);
  const client = useQueryClient();
  return (
    <>
      <div className="actions">
        {can(me, "provision:run") ? <button className="primary" onClick={async () => {
          const run = await api<Row>("/provisioning/reconcile", { method: "POST" });
          inspect({ title: "Reconciliation", body: run });
          client.invalidateQueries({ queryKey: ["reconcile"] });
        }}>Reconcile downstream directory</button> : null}
        {can(me, "provision:run") ? <button onClick={async () => inspect({ title: "SCIM interoperability", body: await api("/connectors/keycloak-scim/tests", { method: "POST" }) })}>Run SCIM checks</button> : null}
      </div>
      <div className="grid-2">
        <div className="table-wrap">
          <table>
            <thead><tr><th>Operation</th><th>Target</th><th>Status</th><th>Correlation</th></tr></thead>
            <tbody>
              {(attempts.data?.items ?? []).slice(0, 40).map((row) => (
                <tr className="clickable" key={String(row.id)} onClick={() => inspect({ title: String(row.operation), body: row })}>
                  <td>{String(row.method)} {String(row.path)}</td>
                  <td>{String(row.target)}</td>
                  <td className="mono">{String(row.status)} {String(row.outcome)}</td>
                  <td className="mono">{String(row.correlation_id)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="card">
          <h2>Reconciliation runs</h2>
          {(runs.data?.items ?? []).map((run) => (
            <button className="chip" key={String(run.id)} onClick={async () => inspect({ title: "Run " + run.id, body: await api(`/provisioning/reconcile/${run.id}`) })}>
              desired {String(run.desired_count)} · actual {String(run.actual_count)}
            </button>
          ))}
        </div>
      </div>
    </>
  );
}

function Reviews({ me }: { me: Me }) {
  const campaigns = useQuery({ queryKey: ["campaigns"], queryFn: () => api<{ items: Row[] }>("/campaigns") });
  const selected = useField("");
  const detail = useQuery({
    queryKey: ["campaign", selected.value],
    queryFn: () => api<Row>(`/campaigns/${selected.value}`),
    enabled: Boolean(selected.value),
  });
  const client = useQueryClient();
  const reason = useField("Access remains appropriate for the current role.");
  const items = (detail.data?.items as Row[] | undefined) ?? [];
  return (
    <div className="grid-2">
      <div className="card">
        <h2>Campaigns</h2>
        {(campaigns.data?.items ?? []).map((row) => (
          <button className="chip" key={String(row.id)} onClick={() => selected.set(String(row.id))}>
            {String(row.name)} · {String(row.progress)}% · due {String(row.due_at)}
          </button>
        ))}
      </div>
      <div className="card">
        <h2>{String(detail.data?.name ?? "Review queue")}</h2>
        <p className="muted">Reviewed {String(detail.data?.reviewed ?? 0)} of {String(detail.data?.total ?? 0)}. Remediation succeeded {String(detail.data?.remediation_succeeded ?? 0)}, failed {String(detail.data?.remediation_failed ?? 0)}.</p>
        <textarea {...reason.bind} rows={3} />
        {items.map((item) => (
          <div className="stage-row" key={String(item.id)}>
            <span className="mono">{String(item.username)}</span>
            <span>{String(item.application)} · {String(item.role)} · {String(item.grant_source)} · {String(item.remediation_status)}</span>
            {can(me, "reviews:decide") ? (
              <span>
                <button onClick={() => decide(String(item.id), "approve", reason.value).then(() => client.invalidateQueries({ queryKey: ["campaign"] }))}>Approve</button>
                <button className="danger" onClick={() => decide(String(item.id), "revoke", reason.value).then(() => client.invalidateQueries({ queryKey: ["campaign"] }))}>Revoke</button>
              </span>
            ) : <span>{String(item.status)}</span>}
          </div>
        ))}
      </div>
    </div>
  );
}

function Policies() {
  const matrix = useQuery({ queryKey: ["matrix"], queryFn: () => api<{ matrix: { applications: Record<string, { actions: Record<string, string[]> }> } }>("/policies/matrix") });
  const username = useField("elena.vasquez");
  const application = useField("northstar-finance");
  const action = useField("payment:approve");
  const result = useMutation({ mutationFn: () => api<Row>("/policies/simulate", { method: "POST", body: JSON.stringify({ username: username.value, application: application.value, action: action.value }) }) });
  const apps = matrix.data?.matrix.applications ?? {};
  return (
    <>
      <div className="card">
        <h2>Authorisation check</h2>
        <p className="muted">This uses the same decision function as the sample applications.</p>
        <div className="filters">
          <input {...username.bind} />
          <input {...application.bind} />
          <input {...action.bind} />
          <button className="primary" onClick={() => result.mutate()}>Evaluate</button>
        </div>
        {result.data ? <p className={result.data.allowed ? "ok" : "bad"}>{String(result.data.reason)}</p> : null}
      </div>
      {Object.entries(apps).map(([name, app]) => (
        <div className="table-wrap" key={name} style={{ marginTop: 12 }}>
          <table>
            <thead><tr><th>{name}</th><th>Roles that grant it</th></tr></thead>
            <tbody>
              {Object.entries(app.actions).map(([permission, roles]) => (
                <tr key={permission}><td className="mono">{permission}</td><td>{roles.join(", ")}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
      <Conflicts />
    </>
  );
}

function Conflicts() {
  const rows = useQuery({ queryKey: ["sod"], queryFn: () => api<{ items: Row[] }>("/sod/conflicts") });
  return (
    <div className="card" style={{ marginTop: 12 }}>
      <h2>Segregation of duties</h2>
      {(rows.data?.items ?? []).map((row) => (
        <div className="event" key={String(row.id)}>
          <span className="mono">{String(row.rule_id)}</span>
          <span>{String(row.subject)} · {String(row.explanation)}</span>
          <span className={row.status === "excepted" ? "warn" : "bad"}>{String(row.status)}</span>
        </div>
      ))}
    </div>
  );
}

function Security({ me }: { me: Me }) {
  const findings = useQuery({ queryKey: ["findings"], queryFn: () => api<{ items: Row[] }>("/findings") });
  const client = useQueryClient();
  return (
    <>
      {can(me, "findings:write") ? <button onClick={() => api("/findings/evaluate", { method: "POST" }).then(() => client.invalidateQueries({ queryKey: ["findings"] }))}>Re-evaluate findings</button> : null}
      <div className="table-wrap">
        <table>
          <thead><tr><th>Severity</th><th>Finding</th><th>Subject</th><th>Status</th><th>Score</th></tr></thead>
          <tbody>
            {(findings.data?.items ?? []).map((row) => (
              <tr key={String(row.id)}>
                <td className={row.severity === "critical" || row.severity === "high" ? "bad" : "warn"}>{String(row.severity)}</td>
                <td>{String(row.title)}<div className="muted mono">{String(row.rule_id)}</div></td>
                <td className="mono">{String(row.subject)}</td>
                <td>{String(row.status)}</td>
                <td className="mono">{String(row.priority_score)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function Audit({ me }: { me: Me }) {
  const actor = useField("");
  const type = useField("");
  const events = useQuery({
    queryKey: ["audit", actor.value, type.value],
    queryFn: () => api<{ items: Row[]; chain: Row }>(`/audit-events?actor=${encodeURIComponent(actor.value)}&event_type=${encodeURIComponent(type.value)}&page_size=50`),
  });
  const client = useQueryClient();
  return (
    <>
      <div className="filters">
        <input {...actor.bind} placeholder="Actor" />
        <input {...type.bind} placeholder="Event type" />
        {can(me, "findings:write") ? <button onClick={() => api("/audit-events/ingest", { method: "POST" }).then(() => client.invalidateQueries({ queryKey: ["audit"] }))}>Ingest Keycloak events</button> : null}
      </div>
      <p className="muted">Audit chain valid: {String((events.data?.chain as Row | undefined)?.valid ?? "—")} · stored {String((events.data?.chain as Row | undefined)?.stored ?? "—")}</p>
      <div className="timeline">
        {(events.data?.items ?? []).map((event) => (
          <div className="event" key={String(event.id)}>
            <span className="mono">{String(event.occurred_at)}</span>
            <span>{String(event.source)} · {String(event.type)} · {String(event.actor)} · {String(event.target)}</span>
            <span className="mono">{String(event.correlation_id).slice(0, 8)}</span>
          </div>
        ))}
      </div>
    </>
  );
}

function Reports({ me }: { me: Me }) {
  const controls = useQuery({ queryKey: ["controls"], queryFn: () => api<{ items: Row[] }>("/controls") });
  const client = useQueryClient();
  const inspect = useUi((state) => state.inspect);
  return (
    <>
      {can(me, "reports:export") ? (
        <div className="actions">
          <button onClick={() => api("/controls/evaluate", { method: "POST" }).then(() => client.invalidateQueries({ queryKey: ["controls"] }))}>Evaluate controls</button>
          {["controls", "privileged", "lifecycle", "sod", "authentication"].map((kind) => (
            <button key={kind} onClick={async () => inspect({ title: kind, body: await api(`/reports/${kind}?fmt=json`, { method: "POST" }) })}>Export {kind} JSON</button>
          ))}
        </div>
      ) : null}
      <div className="table-wrap">
        <table>
          <thead><tr><th>Control</th><th>Objective</th><th>Status</th><th>Evidence</th></tr></thead>
          <tbody>
            {(controls.data?.items ?? []).map((row) => {
              const evaluation = row.evaluation as Row | null;
              return (
                <tr className="clickable" key={String(row.control_id)} onClick={() => inspect({ title: String(row.control_id), body: row })}>
                  <td className="mono">{String(row.control_id)}<div>{String(row.title)}</div></td>
                  <td>{String(row.objective)}</td>
                  <td className={evaluation?.status === "passed" ? "ok" : evaluation?.status === "failed" ? "bad" : "warn"}>{String(evaluation?.status ?? "not evaluated")}</td>
                  <td>{String(evaluation?.summary ?? "No evaluation has been recorded.")}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}

function Metric({ label, value }: { label: string; value: unknown }) {
  return <div className="kpi"><span>{label}</span><b>{value === undefined ? "—" : String(value)}</b></div>;
}

function countFindings(items: Row[]) {
  const names = ["critical", "high", "medium", "low"];
  return names.map((name) => ({ name, value: items.filter((item) => item.severity === name && !["resolved", "accepted"].includes(String(item.status))).length }));
}

function useField(initial: string) {
  const [value, set] = useState(initial);
  return { value, set, bind: { value, onChange: (event: { target: { value: string } }) => set(event.target.value) } };
}

async function decide(id: string, decision: string, reason: string) {
  return api(`/campaigns/items/${id}/decision`, { method: "POST", body: JSON.stringify({ decision, reason }) });
}

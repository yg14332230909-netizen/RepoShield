"""Local Studio Pro HTTP/SSE server."""
from __future__ import annotations

import json
import mimetypes
import os
import shutil
from dataclasses import asdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from ..approval_api import approval_events_summary
from ..approvals import ApprovalCenter, ApprovalStore
from ..models import ApprovalRequest
from .event_stream import StudioEventIndex
from .evidence_exporter import export_evidence
from .redaction import redact_value
from .scenario_runner import list_scenarios, run_scenario


def serve_studio_pro(
    audit_path: str | Path,
    approvals_path: str | Path,
    repo_root: str | Path = ".",
    host: str = "127.0.0.1",
    port: int = 8780,
    bench_report: str | Path | None = None,
    api_key: str | None = None,
    demo_mode: bool = False,
) -> None:
    """Serve the local Studio Pro API and browser UI."""
    required_key = api_key if api_key is not None else os.getenv("REPOSHIELD_STUDIO_API_KEY", "reposhield-local")
    if host not in {"127.0.0.1", "localhost", "::1"} and not required_key:
        raise RuntimeError("Studio Pro refuses non-loopback exposure without a bearer token.")
    index = StudioEventIndex(audit_path)
    approvals = ApprovalStore(approvals_path)
    repo = Path(repo_root).resolve()
    audit = Path(audit_path)
    bench_path = Path(bench_report) if bench_report else None

    class Handler(BaseHTTPRequestHandler):
        server_version = "RepoShieldStudioPro/0.1"

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)
            if path == "/":
                self._html(_studio_html())
                return
            if path.startswith("/assets/"):
                self._static(path.removeprefix("/assets/"))
                return
            if path == "/api/health":
                self._json({"ok": True, "version": "studio.pro.v0.1", "audit_path": str(audit), "approvals_path": str(Path(approvals_path)), "demo_mode": demo_mode})
                return
            if path == "/api/runs":
                self._json({"runs": index.runs()})
                return
            if path.startswith("/api/runs/") and path.endswith("/events"):
                run_id = unquote(path.split("/")[3])
                self._json({"events": index.events(run_id=run_id, limit=int(query.get("limit", ["500"])[0]))})
                return
            if path.startswith("/api/runs/") and path.endswith("/graph"):
                run_id = unquote(path.split("/")[3])
                self._json(index.graph(run_id))
                return
            if path.startswith("/api/runs/"):
                run_id = unquote(path.split("/")[-1])
                run = index.run(run_id)
                self._json(run or {"error": "run not found"}, status=200 if run else 404)
                return
            if path == "/api/events/stream":
                self._stream(query.get("run_id", [None])[0])
                return
            if path.startswith("/api/actions/"):
                action_id = unquote(path.split("/")[-1])
                detail = index.action_detail(action_id)
                self._json(detail or {"error": "action not found"}, status=200 if detail else 404)
                return
            if path == "/api/approvals":
                self._json(approval_events_summary(approvals))
                return
            if path == "/api/scenarios":
                self._json({"scenarios": list_scenarios()})
                return
            if path == "/api/bench/latest":
                self._json(_load_bench(bench_path))
                return
            if path.startswith("/api/export/evidence/"):
                run_id = unquote(path.split("/")[-1])
                out = export_evidence(index, run_id, repo / ".reposhield" / "studio_exports" / run_id)
                self._json({"output": str(out)})
                return
            self._json({"error": "not found"}, status=404)

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path
            if not self._authorized(required_key):
                return
            if path.startswith("/api/scenarios/") and path.endswith("/run"):
                scenario_id = unquote(path.split("/")[3])
                body = self._read_json()
                result = run_scenario(
                    scenario_id,
                    repo_root=body.get("repo") or repo,
                    audit_path=audit,
                    workdir=body.get("workdir"),
                    policy_mode=str(body.get("policy_mode") or "enforce"),
                )
                index.refresh()
                self._json(redact_value(result))
                return
            if path == "/api/admin/clear-records":
                if not demo_mode:
                    self._json({"error": "clear_records_only_available_in_demo_mode"}, status=403)
                    return
                body = self._read_json()
                result = _clear_records(audit, Path(approvals_path), repo, backup=bool(body.get("backup", True)))
                index.refresh()
                self._json(result)
                return
            if path.startswith("/api/approvals/") and path.endswith("/grant"):
                approval_id = unquote(path.split("/")[3])
                req = _find_request(approvals, approval_id)
                if not req:
                    self._json({"error": "approval request not found"}, status=404)
                    return
                body = self._read_json()
                expected_hash = str(body.get("action_hash") or "")
                if expected_hash and expected_hash != req.action_hash:
                    self._json({"error": "action_hash_mismatch"}, status=409)
                    return
                grant = ApprovalCenter().grant(req, constraints=list(body.get("constraints") or ["sandbox_only", "no_network"]), minutes=int(body.get("minutes") or 30), granted_by=str(body.get("granted_by") or "studio"))
                approvals.append_grant(grant)
                self._json({"grant": asdict(grant)})
                return
            if path.startswith("/api/approvals/") and path.endswith("/deny"):
                approval_id = unquote(path.split("/")[3])
                req = _find_request(approvals, approval_id)
                if not req:
                    self._json({"error": "approval request not found"}, status=404)
                    return
                body = self._read_json()
                approvals.append_denial(req, denied_by=str(body.get("denied_by") or "studio"))
                self._json({"approval_request_id": approval_id, "decision": "denied"})
                return
            self._json({"error": "not found"}, status=404)

        def _authorized(self, key: str | None) -> bool:
            if not key:
                return True
            if self.headers.get("Authorization") != f"Bearer {key}":
                self._json({"error": "missing or invalid Authorization bearer token"}, status=401)
                return False
            return True

        def _stream(self, run_id: str | None) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self._cors_headers()
            self.end_headers()
            try:
                for event in index.stream(run_id=run_id):
                    data = json.dumps(event, ensure_ascii=False).encode("utf-8")
                    self.wfile.write(b"event: studio_event\n")
                    self.wfile.write(b"data: " + data + b"\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return

        def _read_json(self) -> dict[str, Any]:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
            if not body:
                return {}
            return json.loads(body.decode("utf-8"))

        def _json(self, payload: Any, status: int = 200) -> None:
            data = json.dumps(redact_value(payload), ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self._cors_headers()
            self.end_headers()
            self.wfile.write(data)

        def _html(self, body: str) -> None:
            data = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self._cors_headers()
            self.end_headers()
            self.wfile.write(data)

        def _static(self, rel_path: str) -> None:
            root = _static_root()
            target = (root / "assets" / rel_path).resolve(strict=False)
            try:
                target.relative_to((root / "assets").resolve(strict=False))
            except ValueError:
                self._json({"error": "invalid static path"}, status=400)
                return
            if not target.exists() or not target.is_file():
                self._json({"error": "static asset not found"}, status=404)
                return
            data = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mimetypes.guess_type(str(target))[0] or "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self._cors_headers()
            self.end_headers()
            self.wfile.write(data)

        def _cors_headers(self) -> None:
            self.send_header("Access-Control-Allow-Origin", f"http://{host}:{port}")
            self.send_header("Vary", "Origin")

        def log_message(self, _format: str, *args: object) -> None:
            return

    if host not in {"127.0.0.1", "localhost", "::1"}:
        print("RepoShield Studio warning: non-loopback host requires bearer auth and local-origin CORS.", flush=True)
    ThreadingHTTPServer((host, port), Handler).serve_forever()


def _find_request(store: ApprovalStore, approval_request_id: str) -> ApprovalRequest | None:
    for event in reversed(store.list_events()):
        if event.get("event_type") == "request" and event.get("payload", {}).get("approval_request_id") == approval_request_id:
            return ApprovalRequest(**event["payload"])
    return None


def _clear_records(audit_path: Path, approvals_path: Path, repo: Path, backup: bool = True) -> dict[str, Any]:
    backup_dir = repo / ".reposhield" / "studio_backups" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backups: list[str] = []
    for path in (audit_path, approvals_path):
        path.parent.mkdir(parents=True, exist_ok=True)
        if backup and path.exists() and path.stat().st_size:
            backup_dir.mkdir(parents=True, exist_ok=True)
            target = backup_dir / path.name
            shutil.copy2(path, target)
            backups.append(str(target))
        path.write_text("", encoding="utf-8")
    return {"ok": True, "cleared": [str(audit_path), str(approvals_path)], "backups": backups, "backup_enabled": backup}


def _load_bench(path: Path | None) -> dict[str, Any]:
    if not path or not path.exists():
        return {"metrics": {}, "samples": []}
    return json.loads(path.read_text(encoding="utf-8"))


def _static_root() -> Path:
    studio_root = Path(__file__).resolve().parents[3] / "web" / "studio"
    dist = studio_root / "dist"
    if (dist / "index.html").exists() or (dist / "react.html").exists():
        return dist
    return studio_root


def _studio_html() -> str:
    root = _static_root()
    for name in ("index.html", "react.html"):
        index = root / name
        if index.exists():
            return index.read_text(encoding="utf-8")
    return _index_html()


def _index_html() -> str:
    return r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>RepoShield Studio Pro</title>
  <style>
    :root { color-scheme: light; --bg:#f7f8fa; --panel:#fff; --line:#d8dee8; --text:#17202a; --muted:#667085; --green:#0f7b45; --red:#b42318; --amber:#b54708; --blue:#175cd3; }
    * { box-sizing: border-box; }
    body { margin:0; font:16px/1.45 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:var(--bg); color:var(--text); }
    header { height:64px; display:flex; align-items:center; justify-content:space-between; padding:0 24px; border-bottom:1px solid var(--line); background:#101828; color:white; }
    h1 { font-size:22px; margin:0; letter-spacing:0; }
    button, select, input { font:inherit; }
    button { border:1px solid var(--line); background:white; border-radius:6px; padding:9px 12px; cursor:pointer; }
    button.primary { background:#175cd3; color:white; border-color:#175cd3; }
    main { display:grid; grid-template-columns:280px minmax(520px,1fr) 380px; gap:14px; padding:14px; height:calc(100vh - 64px); }
    section { background:var(--panel); border:1px solid var(--line); border-radius:8px; overflow:hidden; min-height:0; }
    .section-head { padding:14px 16px; border-bottom:1px solid var(--line); display:flex; align-items:center; justify-content:space-between; gap:8px; }
    .section-head h2 { margin:0; font-size:18px; }
    .scroll { overflow:auto; height:calc(100% - 57px); padding:12px; }
    .run, .event, .metric, .scenario, .approval { border:1px solid var(--line); border-radius:8px; padding:12px; margin-bottom:10px; background:white; }
    .run.active { border-color:#175cd3; box-shadow:0 0 0 2px rgba(23,92,211,.12); }
    .muted { color:var(--muted); font-size:14px; }
    .grid { display:grid; grid-template-columns:repeat(4,minmax(120px,1fr)); gap:10px; margin-bottom:12px; }
    .metric b { display:block; font-size:24px; margin-top:4px; }
    .badge { display:inline-flex; align-items:center; border-radius:999px; padding:3px 9px; font-weight:700; font-size:14px; border:1px solid transparent; }
    .critical { color:var(--red); background:#fef3f2; border-color:#fecdca; }
    .warning { color:var(--amber); background:#fffaeb; border-color:#fedf89; }
    .normal { color:var(--green); background:#ecfdf3; border-color:#abefc6; }
    .info { color:var(--blue); background:#eff8ff; border-color:#b2ddff; }
    .event { min-height:44px; display:grid; grid-template-columns:112px 1fr auto; gap:12px; align-items:start; }
    .event:hover { border-color:#98a2b3; }
    .phase { color:var(--muted); font-weight:700; }
    pre { margin:0; white-space:pre-wrap; overflow:auto; max-height:360px; font:13px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace; background:#f2f4f7; border-radius:6px; padding:10px; }
    .tabs { display:flex; gap:8px; padding:10px 12px; border-bottom:1px solid var(--line); }
    .tabs button.active { background:#101828; color:white; border-color:#101828; }
    .hidden { display:none; }
    .graph { min-height:190px; border:1px dashed var(--line); border-radius:8px; padding:10px; background:#fcfcfd; }
    .node { display:inline-block; padding:7px 9px; border-radius:6px; border:1px solid var(--line); margin:5px; background:white; font-size:14px; }
    @media (max-width: 1100px) { main { grid-template-columns:1fr; height:auto; } section { min-height:360px; } }
  </style>
</head>
<body>
  <header>
    <h1>RepoShield Studio Pro</h1>
    <div><button id="refresh">Refresh</button> <span class="muted" id="health"></span></div>
  </header>
  <main>
    <section>
      <div class="section-head"><h2>Runs</h2><span class="muted" id="run-count">0</span></div>
      <div class="scroll" id="runs"></div>
    </section>
    <section>
      <div class="section-head"><h2>Run Cockpit</h2><span id="selected-run" class="muted">No run selected</span></div>
      <div class="scroll">
        <div class="grid" id="metrics"></div>
        <div class="tabs">
          <button class="active" data-tab="timeline">Timeline</button>
          <button data-tab="graph">Trace Graph</button>
          <button data-tab="attack">Attack Lab</button>
          <button data-tab="bench">Bench</button>
        </div>
        <div id="timeline" class="tab"></div>
        <div id="graph" class="tab hidden"><div class="graph" id="graph-body"></div></div>
        <div id="attack" class="tab hidden"><div id="scenarios"></div></div>
        <div id="bench" class="tab hidden"><pre id="bench-body">{}</pre></div>
      </div>
    </section>
    <section>
      <div class="section-head"><h2>Action Detail</h2><span class="muted">redacted</span></div>
      <div class="scroll">
        <pre id="detail">Click an action event to inspect ActionIR, rules, evidence refs and runtime decision.</pre>
        <h2 style="font-size:18px">Approvals</h2>
        <div id="approvals"></div>
      </div>
    </section>
  </main>
<script>
let selectedRun = null;
let events = [];
let source = null;

const $ = (id) => document.getElementById(id);
async function api(path, opts) {
  const headers = {'Content-Type':'application/json', 'Authorization':'Bearer reposhield-local'};
  const r = await fetch(path, {...opts, headers:{...headers, ...(opts && opts.headers || {})}});
  return r.json();
}
function badge(text, severity) { return `<span class="badge ${severity || 'info'}">${text || 'info'}</span>`; }
function pickDecision(e) { return e.payload.decision || e.payload.effective_decision || e.payload.semantic_action || e.type; }

async function loadAll() {
  const health = await api('/api/health'); $('health').textContent = health.version + ' | ' + health.audit_path;
  const runs = (await api('/api/runs')).runs || [];
  $('run-count').textContent = String(runs.length);
  $('runs').innerHTML = runs.map(r => `<div class="run ${r.run_id === selectedRun ? 'active':''}" data-run="${r.run_id}">
    <b>${r.demo_scenario_id || r.run_id}</b><div class="muted">${r.event_count} events · ${r.action_count} actions</div>
    <div>${badge(r.latest_decision || 'observing', r.blocked_count ? 'critical' : 'normal')}</div>
  </div>`).join('') || '<p class="muted">No audit events yet. Run an Attack Lab scenario.</p>';
  document.querySelectorAll('.run').forEach(el => el.onclick = () => selectRun(el.dataset.run));
  if (!selectedRun && runs[0]) await selectRun(runs[0].run_id);
  await loadScenarios(); await loadApprovals(); await loadBench();
}
async function selectRun(runId) {
  selectedRun = runId; $('selected-run').textContent = runId;
  const run = await api('/api/runs/' + encodeURIComponent(runId));
  $('metrics').innerHTML = [
    ['Events', run.event_count], ['Blocked', run.blocked_count], ['Approvals', run.approval_count], ['Critical', run.critical_count]
  ].map(([k,v]) => `<div class="metric"><span class="muted">${k}</span><b>${v || 0}</b></div>`).join('');
  const data = await api('/api/runs/' + encodeURIComponent(runId) + '/events?limit=500');
  events = data.events || []; renderTimeline();
  renderGraph(await api('/api/runs/' + encodeURIComponent(runId) + '/graph'));
  if (source) source.close();
  source = new EventSource('/api/events/stream?run_id=' + encodeURIComponent(runId));
  source.addEventListener('studio_event', (msg) => { const e = JSON.parse(msg.data); if (!events.find(x => x.event_id === e.event_id)) { events.push(e); renderTimeline(); } });
  await loadAllRunsOnly();
}
async function loadAllRunsOnly() {
  const runs = (await api('/api/runs')).runs || [];
  $('runs').innerHTML = runs.map(r => `<div class="run ${r.run_id === selectedRun ? 'active':''}" data-run="${r.run_id}">
    <b>${r.demo_scenario_id || r.run_id}</b><div class="muted">${r.event_count} events · ${r.action_count} actions</div>
    <div>${badge(r.latest_decision || 'observing', r.blocked_count ? 'critical' : 'normal')}</div>
  </div>`).join('');
  document.querySelectorAll('.run').forEach(el => el.onclick = () => selectRun(el.dataset.run));
}
function renderTimeline() {
  $('timeline').innerHTML = events.map(e => `<div class="event" data-action="${e.payload.action_id || ''}">
    <div><div class="phase">${e.phase}</div><div class="muted">#${e.event_index}</div></div>
    <div><b>${e.summary}</b><div class="muted">${e.type}</div></div>
    <div>${badge(pickDecision(e), e.severity)}</div>
  </div>`).join('');
  document.querySelectorAll('.event[data-action]').forEach(el => { if (el.dataset.action) el.onclick = () => loadAction(el.dataset.action); });
}
async function loadAction(actionId) {
  const detail = await api('/api/actions/' + encodeURIComponent(actionId));
  $('detail').textContent = JSON.stringify(detail, null, 2);
}
function renderGraph(g) {
  const nodes = g.nodes || [], edges = g.edges || [];
  $('graph-body').innerHTML = `<div>${nodes.map(n => `<span class="node ${n.severity}">${n.phase}: ${n.label}</span>`).join('')}</div><pre>${JSON.stringify(edges.slice(0,120), null, 2)}</pre>`;
}
async function loadScenarios() {
  const scenarios = (await api('/api/scenarios')).scenarios || [];
  $('scenarios').innerHTML = scenarios.map(s => `<div class="scenario"><b>${s.name}</b> ${badge(s.kind, s.kind === 'attack' ? 'critical' : 'normal')}
    <div class="muted">${s.description}</div><button class="primary" data-scenario="${s.id}">Run</button></div>`).join('');
  document.querySelectorAll('[data-scenario]').forEach(b => b.onclick = async () => { b.textContent='Running...'; await api('/api/scenarios/' + b.dataset.scenario + '/run', {method:'POST', body:'{}'}); b.textContent='Run'; await loadAll(); });
}
async function loadApprovals() {
  const data = await api('/api/approvals');
  $('approvals').innerHTML = (data.events || []).slice(-8).reverse().map(e => `<div class="approval"><b>${e.event_type}</b><div class="muted">${e.created_at || ''}</div><pre>${JSON.stringify(e.payload, null, 2)}</pre></div>`).join('') || '<p class="muted">No approval events.</p>';
}
async function loadBench() { $('bench-body').textContent = JSON.stringify(await api('/api/bench/latest'), null, 2); }
document.querySelectorAll('[data-tab]').forEach(b => b.onclick = () => {
  document.querySelectorAll('[data-tab]').forEach(x => x.classList.remove('active')); b.classList.add('active');
  document.querySelectorAll('.tab').forEach(x => x.classList.add('hidden')); $(b.dataset.tab).classList.remove('hidden');
});
$('refresh').onclick = loadAll;
loadAll();
</script>
</body>
</html>"""

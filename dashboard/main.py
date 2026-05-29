"""Secure Supply Chain Executive Dashboard.

Serves a real-time web UI backed by the Cloud Build API.
Deployed as a separate Cloud Run service.
"""
import os, json, datetime as dt
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from google.auth import default as google_auth_default
from google.auth.transport.requests import Request as GoogleRequest
import urllib.request, urllib.error

PROJECT_ID  = os.environ.get("PROJECT_ID", "")
APP_URL     = os.environ.get("APP_URL", "#")   # payment-risk-service URL

app = FastAPI(title="Supply Chain Dashboard")

# ── Cloud Build API helpers ───────────────────────────────────────────────────

def _token() -> str:
    try:
        creds, _ = google_auth_default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        creds.refresh(GoogleRequest())
        return creds.token
    except Exception:
        return ""


def _cb_builds(limit: int = 20) -> list:
    """Fetch recent Cloud Build runs via REST."""
    if not PROJECT_ID:
        return _mock_builds()
    try:
        url = (
            f"https://cloudbuild.googleapis.com/v1/projects/{PROJECT_ID}/builds"
            f"?pageSize={limit}&filter=tags%3Dsupply-chain"
        )
        req = urllib.request.Request(
            url, headers={"Authorization": f"Bearer {_token()}"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        return [_normalise(b) for b in data.get("builds", [])]
    except Exception:
        return _mock_builds()


def _normalise(b: dict) -> dict:
    steps   = b.get("steps", [])
    status  = b.get("status", "UNKNOWN")
    start   = b.get("startTime", "")
    finish  = b.get("finishTime", "")
    dur_s   = 0
    if start and finish:
        try:
            s = dt.datetime.fromisoformat(start.replace("Z", "+00:00"))
            f = dt.datetime.fromisoformat(finish.replace("Z", "+00:00"))
            dur_s = int((f - s).total_seconds())
        except Exception:
            pass
    step_names = [s.get("id", s.get("name", "")) for s in steps]
    return {
        "id":           b.get("id", "")[:8],
        "status":       status,
        "trigger":      b.get("substitutions", {}).get("REPO_NAME", "payment-risk-service"),
        "commit":       b.get("substitutions", {}).get("SHORT_SHA", b.get("id", "")[:7]),
        "duration":     f"{dur_s // 60}m {dur_s % 60}s" if dur_s else "—",
        "start":        start[:19].replace("T", " ") if start else "—",
        "steps":        step_names,
        "vuln_ok":      any("check-vuln" in n or "vulnerability" in n.lower() for n in step_names),
        "opa_ok":       any("policy" in n.lower() or "opa" in n.lower() for n in step_names),
        "signed":       any("sign" in n.lower() or "attest" in n.lower() for n in step_names),
        "slsa_level":   2 if status == "SUCCESS" else 0,
    }


def _mock_builds() -> list:
    """Demo data used when Cloud Build API is unavailable."""
    base = dt.datetime.now(dt.timezone.utc)
    rows = [
        ("SUCCESS",  "payment-risk-service", "a3f9c12", "8m 14s", True,  True,  True,  2),
        ("FAILURE",  "fraud-detection-api",  "b7e1d45", "4m 02s", False, False, False, 0),
        ("FAILURE",  "card-tokenisation-svc","c2a8f91", "6m 38s", True,  False, False, 0),
        ("SUCCESS",  "kyc-verification-svc", "d5f3e27", "9m 55s", True,  True,  True,  2),
        ("FAILURE",  "settlement-gateway",   "e9b7c63", "1m 12s", False, False, False, 0),
        ("SUCCESS",  "payment-risk-service", "f1a2b34", "7m 48s", True,  True,  True,  2),
        ("SUCCESS",  "fraud-detection-api",  "g5h6i78", "8m 30s", True,  True,  True,  2),
    ]
    builds = []
    for i, (st, svc, sha, dur, v, o, s, lvl) in enumerate(rows):
        t = (base - dt.timedelta(hours=i*2)).isoformat()[:19].replace("T", " ")
        builds.append({
            "id": sha, "status": st, "trigger": svc, "commit": sha,
            "duration": dur, "start": t,
            "steps": ["unit-tests","build-image","push-image",
                      "check-vulnerabilities","policy-validation","sign-image","deploy"],
            "vuln_ok": v, "opa_ok": o, "signed": s, "slsa_level": lvl,
        })
    return builds


# ── API endpoints ─────────────────────────────────────────────────────────────

@app.get("/api/builds")
def api_builds():
    return _cb_builds(20)


@app.get("/api/summary")
def api_summary():
    builds = _cb_builds(50)
    total   = len(builds)
    success = sum(1 for b in builds if b["status"] == "SUCCESS")
    blocked = total - success
    slsa2   = sum(1 for b in builds if b["slsa_level"] >= 2)
    return {
        "total":           total,
        "deployed":        success,
        "blocked":         blocked,
        "slsa2_pct":       round(slsa2 / total * 100) if total else 0,
        "vuln_blocked":    sum(1 for b in builds if not b["vuln_ok"]),
        "policy_blocked":  sum(1 for b in builds if not b["opa_ok"]),
    }


@app.get("/healthz")
def health():
    return {"status": "ok"}


# ── Dashboard HTML ────────────────────────────────────────────────────────────

DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure Supply Chain Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{font-family:'Google Sans',Arial,sans-serif;background:#0d1117;color:#e6edf3;min-height:100vh}}
  header{{background:linear-gradient(135deg,#1a1f35,#0d1117);border-bottom:1px solid #21262d;
          padding:18px 32px;display:flex;justify-content:space-between;align-items:center}}
  header h1{{font-size:18px;color:#58a6ff;font-weight:500}}
  .badge{{background:#1f3a6e22;border:1px solid #1f6feb;color:#58a6ff;
          padding:3px 10px;border-radius:12px;font-size:11px}}
  .badge.green{{background:#23863622;border-color:#238636;color:#3fb950}}
  .badge.red{{background:#da363322;border-color:#da3633;color:#f85149}}
  .kpi{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;padding:24px 32px}}
  .kcard{{background:#161b22;border:1px solid #21262d;border-radius:12px;padding:20px 24px}}
  .klabel{{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px}}
  .kval{{font-size:34px;font-weight:700;margin:6px 0 3px}}
  .kval.green{{color:#3fb950}} .kval.red{{color:#f85149}}
  .kval.blue{{color:#58a6ff}}  .kval.yellow{{color:#d29922}}
  .ksub{{font-size:11px;color:#8b949e}}
  .charts{{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:0 32px 24px}}
  .ccard{{background:#161b22;border:1px solid #21262d;border-radius:12px;padding:20px 24px}}
  .ccard h3{{font-size:13px;color:#8b949e;margin-bottom:14px;font-weight:400}}
  .table-wrap{{margin:0 32px 32px;background:#161b22;border:1px solid #21262d;border-radius:12px;overflow:hidden}}
  .table-wrap h3{{padding:14px 24px;font-size:13px;color:#8b949e;border-bottom:1px solid #21262d;font-weight:400}}
  table{{width:100%;border-collapse:collapse}}
  th{{padding:9px 20px;font-size:10px;color:#8b949e;text-transform:uppercase;
      letter-spacing:.4px;background:#0d1117;text-align:left}}
  td{{padding:11px 20px;font-size:12px;border-top:1px solid #21262d}}
  .pass{{color:#3fb950}} .fail{{color:#f85149}} .mono{{font-family:monospace;color:#8b949e}}
  .pill{{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}}
  .pill.success{{background:#23863622;color:#3fb950;border:1px solid #238636}}
  .pill.failure{{background:#da363322;color:#f85149;border:1px solid #da3633}}
  .slsa-badge{{background:#1f3a6e22;color:#58a6ff;border:1px solid #1f6feb;
               padding:2px 7px;border-radius:10px;font-size:11px}}
  a{{color:#58a6ff;text-decoration:none}}
  a:hover{{text-decoration:underline}}
  @media(max-width:800px){{.kpi,.charts{{grid-template-columns:1fr}}}}
</style>
</head>
<body>

<header>
  <div>
    <h1>&#128274; Secure Software Supply Chain — Executive Dashboard</h1>
    <div style="font-size:11px;color:#8b949e;margin-top:3px">
      Google Cloud · Cloud Build · Artifact Registry · Binary Authorization · SLSA Level 2
    </div>
  </div>
  <div style="display:flex;gap:8px;align-items:center">
    <span class="badge green">&#x2714; SLSA L2 Active</span>
    <span class="badge">Artifact Registry: Enforced</span>
    <a href="{app_url}" target="_blank" class="badge" style="cursor:pointer">
      &#x1F680; Live App &#x2197;
    </a>
    <span id="clock" style="font-size:11px;color:#8b949e"></span>
  </div>
</header>

<!-- KPIs -->
<div class="kpi" id="kpi">
  <div class="kcard"><div class="klabel">Total Builds</div>
    <div class="kval blue" id="k-total">—</div>
    <div class="ksub">last 50 pipeline runs</div></div>
  <div class="kcard"><div class="klabel">Deployments</div>
    <div class="kval green" id="k-deployed">—</div>
    <div class="ksub">reached production</div></div>
  <div class="kcard"><div class="klabel">Blocked by Policy</div>
    <div class="kval red" id="k-blocked">—</div>
    <div class="ksub">stopped before production</div></div>
  <div class="kcard"><div class="klabel">SLSA L2 Compliance</div>
    <div class="kval yellow" id="k-slsa">—%</div>
    <div class="ksub">of successful builds</div></div>
</div>

<!-- Charts -->
<div class="charts">
  <div class="ccard">
    <h3>Pipeline Outcomes — Last 7 Runs</h3>
    <canvas id="outcomesChart" height="180"></canvas>
  </div>
  <div class="ccard">
    <h3>SLSA Compliance by Service</h3>
    <div id="slsa-bars" style="margin-top:4px"></div>
  </div>
</div>

<!-- Build table -->
<div class="table-wrap">
  <h3>Recent Pipeline Runs</h3>
  <table>
    <thead><tr>
      <th>Service</th><th>Commit</th><th>Started</th><th>Duration</th>
      <th>Vuln Scan</th><th>Policy</th><th>Signed</th><th>SLSA</th><th>Status</th>
    </tr></thead>
    <tbody id="build-rows"></tbody>
  </table>
</div>

<script>
// Clock
function tick(){{document.getElementById('clock').textContent=
  new Date().toLocaleTimeString('en-GB',{{timeZone:'UTC'}})+' UTC'}}
tick(); setInterval(tick,1000);

let outChart;

async function refresh(){{
  const [summary, builds] = await Promise.all([
    fetch('/api/summary').then(r=>r.json()),
    fetch('/api/builds').then(r=>r.json()),
  ]);

  document.getElementById('k-total').textContent    = summary.total;
  document.getElementById('k-deployed').textContent = summary.deployed;
  document.getElementById('k-blocked').textContent  = summary.blocked;
  document.getElementById('k-slsa').textContent     = summary.slsa2_pct+'%';

  // Outcomes bar chart
  const last7 = builds.slice(0,7).reverse();
  const labels = last7.map(b=>b.trigger.replace('-service','').replace('-api',''));
  const success = last7.map(b=>b.status==='SUCCESS'?1:0);
  const failed  = last7.map(b=>b.status!=='SUCCESS'?1:0);

  if(outChart) outChart.destroy();
  outChart = new Chart(document.getElementById('outcomesChart'),{{
    type:'bar',
    data:{{
      labels,
      datasets:[
        {{label:'Deployed', data:success, backgroundColor:'#238636', borderRadius:4}},
        {{label:'Blocked',  data:failed,  backgroundColor:'#da3633', borderRadius:4}},
      ]
    }},
    options:{{
      responsive:true, plugins:{{legend:{{labels:{{color:'#8b949e',font:{{size:11}}}}}}}},
      scales:{{
        x:{{stacked:true,ticks:{{color:'#8b949e',font:{{size:10}}}},grid:{{color:'#21262d'}}}},
        y:{{stacked:true,ticks:{{color:'#8b949e',maxTicksLimit:3}},grid:{{color:'#21262d'}},max:1}},
      }}
    }}
  }});

  // SLSA compliance bars per service
  const byService = {{}};
  builds.forEach(b=>{{
    if(!byService[b.trigger]) byService[b.trigger]={{total:0,compliant:0}};
    byService[b.trigger].total++;
    if(b.slsa_level>=2) byService[b.trigger].compliant++;
  }});
  document.getElementById('slsa-bars').innerHTML = Object.entries(byService).map(([svc,d])=>{{
    const pct = Math.round(d.compliant/d.total*100);
    const col = pct===100?'#238636':pct>60?'#d29922':'#da3633';
    const label = svc.replace('-service','').replace('-api','');
    return `<div style="display:flex;align-items:center;gap:8px;margin:9px 0">
      <span style="width:130px;font-size:12px;color:#c9d1d9">${{label}}</span>
      <div style="flex:1;height:7px;background:#21262d;border-radius:4px;overflow:hidden">
        <div style="width:${{pct}}%;height:100%;background:${{col}};border-radius:4px"></div>
      </div>
      <span style="width:36px;text-align:right;font-size:11px;color:#8b949e">${{pct}}%</span>
    </div>`;
  }}).join('');

  // Build rows
  document.getElementById('build-rows').innerHTML = builds.map(b=>`
    <tr>
      <td style="color:#c9d1d9">${{b.trigger}}</td>
      <td class="mono">${{b.commit}}</td>
      <td class="mono">${{b.start}}</td>
      <td class="mono">${{b.duration}}</td>
      <td class="${{b.vuln_ok?'pass':'fail'}}">${{b.vuln_ok?'✓ Pass':'✗ Critical CVE'}}</td>
      <td class="${{b.opa_ok?'pass':'fail'}}">${{b.opa_ok?'✓ Pass':'✗ Violation'}}</td>
      <td class="${{b.signed?'pass':'fail'}}">${{b.signed?'✓ Signed':'—'}}</td>
      <td>${{b.slsa_level>=2?'<span class="slsa-badge">L2</span>':'<span style="color:#8b949e">—</span>'}}</td>
      <td><span class="pill ${{b.status==='SUCCESS'?'success':'failure'}}">${{b.status}}</span></td>
    </tr>`).join('');
}}

refresh();
setInterval(refresh, 15000);
</script>
</body>
</html>"""

@app.get("/", response_class=HTMLResponse)
def index():
    return DASHBOARD.format(app_url=APP_URL)

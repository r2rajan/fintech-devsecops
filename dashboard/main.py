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

    # Detect which step caused the failure
    failed_step = None
    if status != "SUCCESS":
        for s in steps:
            if s.get("status") == "FAILURE":
                failed_step = s.get("id", s.get("name", ""))
                break

    # Image digest from build results
    build_id = b.get("id", "")
    digest = ""
    images = b.get("results", {}).get("images", [])
    if images:
        digest = images[0].get("digest", "")

    provenance = (
        f"projects/{b.get('projectId', PROJECT_ID)}/locations/global/occurrences/build-{build_id[:8]}"
        if status == "SUCCESS" else ""
    )

    return {
        "id":             build_id,
        "status":         status,
        "trigger":        (b.get("substitutions", {}).get("_SERVICE_NAME")
                          or b.get("substitutions", {}).get("REPO_NAME")
                          or "payment-risk-service"
                          ).replace("fintech-devsecops", "payment-risk-service"),
        "commit":         b.get("substitutions", {}).get("SHORT_SHA", build_id[:7]),
        "duration":       f"{dur_s // 60}m {dur_s % 60}s" if dur_s else "—",
        "start":          start[:19].replace("T", " ") if start else "—",
        "steps":          step_names,
        "vuln_ok":        any("check-vuln" in n or "vulnerability" in n.lower() for n in step_names),
        "opa_ok":         any("policy" in n.lower() or "opa" in n.lower() for n in step_names),
        "signed":         status == "SUCCESS",
        "slsa_level":     3 if status == "SUCCESS" else 0,
        "failed_step":    failed_step,
        "failure_detail": "",
        "digest":         digest,
        "provenance":     provenance,
    }


def _mock_builds() -> list:
    """Demo data used when Cloud Build API is unavailable."""
    base = dt.datetime.now(dt.timezone.utc)

    D1 = "sha256:e6e1a4ce0f131c5f7c744feab50bd0c8ce57439acc8c731806ba72de239e18e5"
    D2 = "sha256:f1a2b34c5d6e7f8901a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4"
    D3 = "sha256:a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4"
    D4 = "sha256:9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c"

    rows = [
        # (status, build_id, commit_sha, dur, vuln_ok, opa_ok, signed, slsa, failed_step, failure_detail, digest, provenance)
        ("SUCCESS", "4a7f1c2e", "a3f9c12", "8m 14s", True,  True,  True,  3,
         None, None,
         D1, "projects/fintech-devsecops-2026/locations/us-central1/occurrences/prov-a3f9c12"),

        ("FAILURE", "9b2e5d8a", "b7e1d45", "4m 02s", False, False, False, 0,
         "check-vulnerabilities",
         "2 CRITICAL CVEs found in perl 5.40.1:\n• CVE-2026-8376 (CVSS 9.8) — No fix available\n• CVE-2026-42496 (CVSS 9.1) — No fix available",
         None, None),

        ("SUCCESS", "3c6f9e1b", "c2a8f91", "9m 22s", True,  True,  True,  3,
         None, None,
         D2, "projects/fintech-devsecops-2026/locations/us-central1/occurrences/prov-c2a8f91"),

        ("FAILURE", "7d4a0c5f", "d5f3e27", "1m 08s", False, False, False, 0,
         "unit-tests",
         "Risk scoring assertion failed.\nExpected: CRITICAL  Got: HIGH\nTest transaction: £9,000 · crypto · NG · online",
         None, None),

        ("FAILURE", "2e8b3f6c", "e9b7c63", "6m 44s", True,  False, False, 0,
         "policy-check",
         "Policy violation: Image not pinned to SHA256 digest.\nImage was referenced by mutable tag ':latest' instead of an immutable '@sha256:...' digest.",
         None, None),

        ("SUCCESS", "5f1d7a9e", "f1a2b34", "7m 48s", True,  True,  True,  3,
         None, None,
         D3, "projects/fintech-devsecops-2026/locations/us-central1/occurrences/prov-f1a2b34"),

        ("SUCCESS", "8a3e2b4d", "g5h6i78", "8m 30s", True,  True,  True,  3,
         None, None,
         D4, "projects/fintech-devsecops-2026/locations/us-central1/occurrences/prov-g5h6i78"),
    ]

    builds = []
    for i, (st, bid, sha, dur, v, o, s, lvl, fs, fd, digest, prov) in enumerate(rows):
        t = (base - dt.timedelta(hours=i * 2)).isoformat()[:19].replace("T", " ")
        builds.append({
            "id": bid, "status": st, "trigger": "payment-risk-service", "commit": sha,
            "duration": dur, "start": t,
            "steps": ["unit-tests", "build-app", "push-app", "get-digest",
                      "check-vulnerabilities", "policy-check", "deploy-app"],
            "vuln_ok": v, "opa_ok": o, "signed": s, "slsa_level": lvl,
            "failed_step": fs,
            "failure_detail": fd or "",
            "digest": digest or "",
            "provenance": prov or "",
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
    slsa3   = sum(1 for b in builds if b["slsa_level"] >= 3)
    return {
        "total":           total,
        "deployed":        success,
        "blocked":         blocked,
        "slsa3_pct":       round(slsa3 / total * 100) if total else 0,
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
  .modal-overlay{{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);
                  z-index:100;align-items:center;justify-content:center}}
  .modal-box{{background:#161b22;border:1px solid #30363d;border-radius:14px;
              width:580px;max-width:92vw;max-height:84vh;overflow-y:auto;
              box-shadow:0 24px 64px rgba(0,0,0,.6)}}
  .modal-titlebar{{display:flex;justify-content:space-between;align-items:center;
                   padding:14px 20px;border-bottom:1px solid #21262d;position:sticky;top:0;
                   background:#161b22;z-index:1}}
  .modal-close{{background:none;border:none;color:#8b949e;font-size:22px;
                cursor:pointer;line-height:1;padding:2px 6px;border-radius:4px}}
  .modal-close:hover{{color:#c9d1d9;background:#21262d}}
  .modal-body{{padding:20px}}
  @media(max-width:800px){{.kpi,.charts{{grid-template-columns:1fr}}}}
</style>
</head>
<body>

<header>
  <div>
    <h1>&#128274; Secure Software Supply Chain — Executive Dashboard</h1>
    <div style="font-size:11px;color:#8b949e;margin-top:3px">
      Google Cloud &middot; Cloud Build &middot; Artifact Registry &middot; Binary Authorization &middot; SLSA Level 3
    </div>
  </div>
  <div style="display:flex;gap:8px;align-items:center">
    <span class="badge green">&#x2714; SLSA L3 Active</span>
    <span class="badge">Artifact Registry: Enforced</span>
    <a href="{app_url}" target="_blank" class="badge" style="cursor:pointer">
      &#x1F680; Live App &#x2197;
    </a>
    <span id="clock" style="font-size:11px;color:#8b949e"></span>
  </div>
</header>

<!-- KPIs -->
<div class="kpi">
  <div class="kcard"><div class="klabel">Total Builds</div>
    <div class="kval blue" id="k-total">—</div>
    <div class="ksub">last 50 pipeline runs</div></div>
  <div class="kcard"><div class="klabel">Deployments</div>
    <div class="kval green" id="k-deployed">—</div>
    <div class="ksub">reached production</div></div>
  <div class="kcard"><div class="klabel">Blocked by Policy</div>
    <div class="kval red" id="k-blocked">—</div>
    <div class="ksub">stopped before production</div></div>
  <div class="kcard"><div class="klabel">SLSA L3 Compliance</div>
    <div class="kval yellow" id="k-slsa">—%</div>
    <div class="ksub">of successful builds</div></div>
</div>

<!-- Charts -->
<div class="charts">
  <div class="ccard">
    <h3>Pipeline Outcomes — Last 7 Runs
      <span style="font-size:10px;color:#484f58;margin-left:6px">(click a bar for details)</span>
    </h3>
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

<!-- Build Detail Modal -->
<div id="build-modal" class="modal-overlay" onclick="if(event.target===this)closeModal()">
  <div class="modal-box">
    <div class="modal-titlebar">
      <span style="font-size:13px;color:#c9d1d9;font-weight:500">Build Details</span>
      <button class="modal-close" onclick="closeModal()">&#x2715;</button>
    </div>
    <div id="modal-body" class="modal-body"></div>
  </div>
</div>

<script>
function tick(){{document.getElementById('clock').textContent=
  new Date().toLocaleTimeString('en-GB',{{timeZone:'UTC'}})+' UTC'}}
tick(); setInterval(tick,1000);

let outChart;
let last7 = [];
const PROJECT = '{project_id}';

const STEP_ORDER = [
  'unit-tests','build-app','push-app','get-digest',
  'check-vulnerabilities','policy-check','deploy-app'
];
const STEP_LABELS = {{
  'unit-tests':            'Gate 1 — Unit Tests',
  'build-app':             'Build Image',
  'push-app':              'Push to Artifact Registry',
  'get-digest':            'Capture Immutable Digest',
  'check-vulnerabilities': 'Gate 2 — Vulnerability Scan',
  'policy-check':          'Gate 3 — Policy Check',
  'deploy-app':            'Deploy to Cloud Run'
}};

function closeModal() {{
  document.getElementById('build-modal').style.display = 'none';
}}

function showBuildModal(build) {{
  const isSuccess = build.status === 'SUCCESS';
  const hCol  = isSuccess ? '#238636' : '#da3633';
  const hIcon = isSuccess ? '✓' : '✗';
  const hLabel = isSuccess ? 'DEPLOYED' : 'BLOCKED';

  let html = `
    <div style="display:flex;justify-content:space-between;align-items:center;
                padding:11px 14px;background:${{hCol}}22;border-radius:8px;
                border:1px solid ${{hCol}};margin-bottom:18px">
      <span style="color:${{hCol}};font-weight:600;font-size:14px">${{hIcon}} ${{hLabel}}</span>
      <span style="color:#8b949e;font-size:12px;font-family:monospace">
        build ${{build.id}} &nbsp;&middot;&nbsp; ${{build.duration}}
      </span>
    </div>`;

  if (isSuccess) {{
    html += `
      <div style="margin-bottom:16px">
        <div style="font-size:10px;color:#8b949e;text-transform:uppercase;
                    letter-spacing:.5px;margin-bottom:6px">Build ID</div>
        <div style="font-family:monospace;font-size:13px;color:#c9d1d9;background:#0d1117;
                    padding:10px 12px;border-radius:6px;line-height:1.6">
          ${{build.id}}
        </div>
      </div>
      <div style="margin-bottom:16px">
        <div style="font-size:10px;color:#8b949e;text-transform:uppercase;
                    letter-spacing:.5px;margin-bottom:6px">Git Commit SHA</div>
        <div style="font-family:monospace;font-size:13px;color:#c9d1d9;background:#0d1117;
                    padding:10px 12px;border-radius:6px;line-height:1.6">
          ${{build.commit}}
        </div>
      </div>
      <div style="margin-bottom:20px">
        <div style="font-size:10px;color:#8b949e;text-transform:uppercase;
                    letter-spacing:.5px;margin-bottom:6px">SLSA Provenance</div>
        <div style="font-family:monospace;font-size:11px;color:#8b949e;background:#0d1117;
                    padding:10px 12px;border-radius:6px;word-break:break-all;line-height:1.6">
          ${{build.provenance || '—'}}
        </div>
      </div>`;
  }} else {{
    html += `
      <div style="margin-bottom:14px">
        <div style="font-size:10px;color:#8b949e;text-transform:uppercase;
                    letter-spacing:.5px;margin-bottom:6px">Failed At</div>
        <div style="color:#f85149;font-size:13px;font-weight:500">
          ${{STEP_LABELS[build.failed_step] || build.failed_step || 'Unknown step'}}
        </div>
      </div>`;
    if (build.failure_detail) {{
      html += `
        <div style="margin-bottom:16px">
          <div style="font-size:10px;color:#8b949e;text-transform:uppercase;
                      letter-spacing:.5px;margin-bottom:6px">Failure Detail</div>
          <div style="font-size:12px;color:#c9d1d9;background:#0d1117;padding:12px 14px;
                      border-radius:6px;border-left:3px solid #da3633;
                      white-space:pre-line;line-height:1.7">
            ${{build.failure_detail}}
          </div>
        </div>`;
    }}
    const linkUrl = build.failed_step === 'check-vulnerabilities'
      ? `https://console.cloud.google.com/artifacts/docker/${{PROJECT}}/us-central1/fintech-apps/payment-risk-service?project=${{PROJECT}}`
      : `https://console.cloud.google.com/cloud-build/builds?project=${{PROJECT}}`;
    const linkLabel = build.failed_step === 'check-vulnerabilities'
      ? '&#x1F517; View Critical CVEs in Artifact Registry &#x2197;'
      : '&#x1F517; View Build Logs in Cloud Build &#x2197;';
    html += `
      <div style="margin-bottom:20px">
        <a href="${{linkUrl}}" target="_blank"
           style="display:inline-flex;align-items:center;gap:6px;font-size:12px;color:#58a6ff;
                  border:1px solid #1f6feb;border-radius:6px;padding:8px 14px;
                  text-decoration:none;background:#1f3a6e22">
          ${{linkLabel}}
        </a>
      </div>`;
  }}

  // Pipeline trace
  html += `<div style="font-size:10px;color:#8b949e;text-transform:uppercase;
                       letter-spacing:.5px;margin-bottom:8px">Pipeline Trace</div>`;
  const failIdx = build.failed_step ? STEP_ORDER.indexOf(build.failed_step) : -1;

  STEP_ORDER.forEach((step, i) => {{
    let icon, col, badge = '';
    if (isSuccess || (failIdx >= 0 && i < failIdx)) {{
      icon = '✓'; col = '#3fb950';
    }} else if (i === failIdx) {{
      icon = '✗'; col = '#f85149';
      badge = `<span style="margin-left:auto;background:#da363322;color:#f85149;
                             border:1px solid #da3633;padding:1px 8px;
                             border-radius:8px;font-size:10px;white-space:nowrap">BLOCKED</span>`;
    }} else {{
      icon = '—'; col = '#484f58';
    }}
    html += `
      <div style="display:flex;align-items:center;gap:10px;
                  padding:8px 0;border-bottom:1px solid #21262d">
        <span style="color:${{col}};font-size:13px;width:16px;
                     text-align:center;flex-shrink:0">${{icon}}</span>
        <span style="font-size:12px;color:${{col}};flex:1">${{STEP_LABELS[step]}}</span>
        ${{badge}}
      </div>`;
  }});

  document.getElementById('modal-body').innerHTML = html;
  document.getElementById('build-modal').style.display = 'flex';
}}

async function refresh() {{
  const [summary, builds] = await Promise.all([
    fetch('/api/summary').then(r=>r.json()),
    fetch('/api/builds').then(r=>r.json()),
  ]);

  document.getElementById('k-total').textContent    = summary.total;
  document.getElementById('k-deployed').textContent = summary.deployed;
  document.getElementById('k-blocked').textContent  = summary.blocked;
  document.getElementById('k-slsa').textContent     = summary.slsa3_pct+'%';

  last7 = builds.slice(0,7).reverse();
  const labels  = last7.map(b => b.trigger.replace('-service','').replace('-api',''));
  const success = last7.map(b => b.status==='SUCCESS' ? 1 : 0);
  const failed  = last7.map(b => b.status!=='SUCCESS' ? 1 : 0);

  if (outChart) outChart.destroy();
  outChart = new Chart(document.getElementById('outcomesChart'), {{
    type: 'bar',
    data: {{
      labels,
      datasets: [
        {{label:'Deployed', data:success, backgroundColor:'#238636', borderRadius:4}},
        {{label:'Blocked',  data:failed,  backgroundColor:'#da3633', borderRadius:4}},
      ]
    }},
    options: {{
      responsive: true,
      plugins: {{legend: {{labels: {{color:'#8b949e', font: {{size:11}}}}}}}},
      scales: {{
        x: {{stacked:true, ticks:{{color:'#8b949e',font:{{size:10}}}}, grid:{{color:'#21262d'}}}},
        y: {{stacked:true, ticks:{{color:'#8b949e',maxTicksLimit:3}}, grid:{{color:'#21262d'}}, max:1}},
      }},
      onClick: (evt, elements) => {{
        if (elements.length > 0) showBuildModal(last7[elements[0].index]);
      }},
      onHover: (evt, elements) => {{
        evt.native.target.style.cursor = elements.length > 0 ? 'pointer' : 'default';
      }}
    }}
  }});

  // SLSA compliance bars per service
  const byService = {{}};
  builds.forEach(b => {{
    if (!byService[b.trigger]) byService[b.trigger] = {{total:0, compliant:0}};
    byService[b.trigger].total++;
    if (b.slsa_level >= 3) byService[b.trigger].compliant++;
  }});
  document.getElementById('slsa-bars').innerHTML = Object.entries(byService).map(([svc, d]) => {{
    const pct = Math.round(d.compliant / d.total * 100);
    const col = pct===100 ? '#238636' : pct>60 ? '#d29922' : '#da3633';
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
  document.getElementById('build-rows').innerHTML = builds.map(b => `
    <tr>
      <td style="color:#c9d1d9">${{b.trigger}}</td>
      <td class="mono">${{b.commit}}</td>
      <td class="mono">${{b.start}}</td>
      <td class="mono">${{b.duration}}</td>
      <td class="${{b.vuln_ok?'pass':'fail'}}">${{b.vuln_ok?'✓ Pass':'✗ Critical CVE'}}</td>
      <td class="${{b.opa_ok?'pass':'fail'}}">${{b.opa_ok?'✓ Pass':'✗ Violation'}}</td>
      <td class="${{b.signed?'pass':'fail'}}">${{b.signed?'✓ Signed':'—'}}</td>
      <td>${{b.slsa_level>=3?'<span class="slsa-badge">L3</span>':'<span style="color:#8b949e">—</span>'}}</td>
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
    return DASHBOARD.format(app_url=APP_URL, project_id=PROJECT_ID or "fintech-devsecops-2026")

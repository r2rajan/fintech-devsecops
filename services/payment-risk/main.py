"""Payment Risk Scoring Service — Secure Supply Chain Demo.

Serves both a web UI (GET /) and a JSON API (POST /score).
Deployed via a Cloud Build pipeline that generates SLSA provenance.
"""
import os, uuid, datetime as dt
from collections import deque
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

PROJECT_ID = os.environ.get("PROJECT_ID", "demo")
BUILD_ID   = os.environ.get("BUILD_ID", "local")
COMMIT_SHA = os.environ.get("COMMIT_SHA", "local")
IMAGE_TAG  = os.environ.get("IMAGE_TAG", "latest")

app = FastAPI(title="Payment Risk Scoring Service")

# In-memory log for the demo (last 20 transactions)
recent: deque = deque(maxlen=20)

# ── Domain logic ──────────────────────────────────────────────────────────────

HIGH_RISK_COUNTRIES   = {"NG", "RO", "VN", "PK", "IR", "KP"}
HIGH_RISK_CATEGORIES  = {"gambling", "crypto", "wire_transfer", "money_service"}
RISK_COLOURS          = {"LOW": "#22c55e", "MEDIUM": "#f59e0b",
                         "HIGH": "#f97316", "CRITICAL": "#ef4444"}

class Transaction(BaseModel):
    transaction_id: str = ""
    amount_gbp: float
    merchant_category: str
    country_code: str
    cardholder_id: str = "demo-user"
    channel: str = "online"

def _score(tx: Transaction) -> dict:
    score, factors = 0, []
    if not tx.transaction_id:
        tx.transaction_id = f"TXN-{uuid.uuid4().hex[:8].upper()}"

    if tx.amount_gbp > 5000:
        score += 35; factors.append(f"Very high value: £{tx.amount_gbp:,.2f}")
    elif tx.amount_gbp > 1000:
        score += 20; factors.append(f"Elevated value: £{tx.amount_gbp:,.2f}")
    elif tx.amount_gbp > 500:
        score += 10; factors.append(f"Moderate value: £{tx.amount_gbp:,.2f}")

    if tx.country_code.upper() in HIGH_RISK_COUNTRIES:
        score += 30; factors.append(f"High-risk country: {tx.country_code.upper()}")

    if tx.merchant_category.lower() in HIGH_RISK_CATEGORIES:
        score += 25; factors.append(f"High-risk category: {tx.merchant_category}")

    if tx.channel == "online" and tx.amount_gbp > 200:
        score += 10; factors.append("Online channel with elevated amount")

    score = min(score, 100)
    if score >= 75: level, action = "CRITICAL", "BLOCK"
    elif score >= 50: level, action = "HIGH",     "REVIEW"
    elif score >= 25: level, action = "MEDIUM",   "APPROVE"
    else:             level, action = "LOW",       "APPROVE"

    result = {
        "transaction_id": tx.transaction_id,
        "risk_score": score,
        "risk_level": level,
        "recommended_action": action,
        "factors": factors or ["No elevated risk factors detected"],
        "scored_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "colour": RISK_COLOURS[level],
    }
    recent.appendleft(result)
    return result

# ── API ───────────────────────────────────────────────────────────────────────

@app.post("/score")
def score_transaction(tx: Transaction):
    return _score(tx)

@app.get("/recent")
def get_recent():
    return list(recent)

@app.get("/healthz")
def health():
    return {"status": "ok"}

# ── Web UI ────────────────────────────────────────────────────────────────────

PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NovaPay - Payment Risk Scoring Service</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{font-family:'Google Sans',Arial,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}}
  header{{background:linear-gradient(135deg,#1e3a5f,#0f172a);padding:18px 32px;
          border-bottom:1px solid #1e293b;display:flex;justify-content:space-between;align-items:center}}
  header h1{{font-size:18px;color:#60a5fa;font-weight:500}}
  .badge{{background:#1e3a5f;border:1px solid #3b82f6;color:#93c5fd;
          padding:3px 10px;border-radius:12px;font-size:11px}}
  .badge.green{{background:#052e16;border-color:#22c55e;color:#4ade80}}
  .container{{max-width:1100px;margin:0 auto;padding:32px 24px;
              display:grid;grid-template-columns:1fr 1fr;gap:24px}}
  .card{{background:#1e293b;border:1px solid #334155;border-radius:14px;padding:28px}}
  .card h2{{font-size:15px;color:#94a3b8;margin-bottom:20px;font-weight:500}}
  label{{display:block;font-size:12px;color:#94a3b8;margin-bottom:4px;margin-top:14px}}
  input,select{{width:100%;padding:10px 12px;background:#0f172a;border:1px solid #334155;
                border-radius:8px;color:#e2e8f0;font-size:14px;outline:none}}
  input:focus,select:focus{{border-color:#3b82f6}}
  button{{margin-top:20px;width:100%;padding:12px;background:#2563eb;border:none;
          border-radius:8px;color:white;font-size:14px;cursor:pointer;font-weight:500}}
  button:hover{{background:#1d4ed8}}
  .result{{display:none;margin-top:20px;border-radius:10px;padding:20px;border:2px solid #334155}}
  .score-ring{{width:90px;height:90px;border-radius:50%;display:flex;align-items:center;
               justify-content:center;font-size:28px;font-weight:700;margin:0 auto 12px;
               border:4px solid currentColor}}
  .level{{font-size:22px;font-weight:700;text-align:center;margin-bottom:4px}}
  .action{{font-size:13px;text-align:center;color:#94a3b8;margin-bottom:16px}}
  .factors{{font-size:12px}}
  .factors li{{padding:5px 0;border-top:1px solid #1e293b;color:#94a3b8}}
  .factors li:first-child{{border-top:none}}
  .recent-list{{max-height:420px;overflow-y:auto}}
  .tx-row{{display:flex;justify-content:space-between;align-items:center;
           padding:10px 0;border-bottom:1px solid #1e293b;font-size:13px}}
  .tx-id{{color:#60a5fa;font-family:monospace;font-size:12px}}
  .tx-pill{{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}}
  .build-info{{font-size:11px;color:#475569;margin-top:8px;font-family:monospace}}
  @media(max-width:700px){{.container{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<header>
  <div>
    <h1>&#128274; NovaPay - Payment Risk Scoring Service</h1>
    <div style="font-size:11px;color:#475569;margin-top:3px">
      Deployed via Cloud Build · SLSA Provenance Verified
    </div>
  </div>
  <div style="display:flex;gap:8px">
    <span class="badge green">&#x2714; SLSA L3 Compliant</span>
    <span class="badge">Build: {build_id}</span>
  </div>
</header>

<div class="container">

  <!-- Score form -->
  <div class="card">
    <h2>&#128202; Score a Transaction</h2>
    <form id="form">
      <label>Amount (£)</label>
      <input type="number" id="amount" placeholder="e.g. 2500" step="0.01" required>
      <label>Merchant Category</label>
      <select id="category">
        <option value="retail">Retail</option>
        <option value="restaurant">Restaurant</option>
        <option value="travel">Travel</option>
        <option value="gambling">Gambling &#x26A0;</option>
        <option value="crypto">Cryptocurrency &#x26A0;</option>
        <option value="wire_transfer">Wire Transfer &#x26A0;</option>
        <option value="money_service">Money Service &#x26A0;</option>
        <option value="grocery">Grocery</option>
      </select>
      <label>Country Code</label>
      <select id="country">
        <option value="GB">🇬🇧 GB — United Kingdom</option>
        <option value="US">🇺🇸 US — United States</option>
        <option value="DE">🇩🇪 DE — Germany</option>
        <option value="FR">🇫🇷 FR — France</option>
        <option value="NG">🇳🇬 NG — Nigeria &#x26A0;</option>
        <option value="RO">🇷🇴 RO — Romania &#x26A0;</option>
        <option value="VN">🇻🇳 VN — Vietnam &#x26A0;</option>
        <option value="PK">🇵🇰 PK — Pakistan &#x26A0;</option>
        <option value="KP">🇰🇵 KP — North Korea &#x26A0;</option>
      </select>
      <label>Channel</label>
      <select id="channel">
        <option value="online">Online</option>
        <option value="in-store">In-Store</option>
        <option value="atm">ATM</option>
      </select>
      <button type="submit">&#x26A1; Score Transaction</button>
    </form>

    <div class="result" id="result">
      <div class="score-ring" id="ring"></div>
      <div class="level" id="level"></div>
      <div class="action" id="action-text"></div>
      <ul class="factors" id="factors"></ul>
      <div class="build-info">
        txn: <span id="txn-id"></span> &nbsp;·&nbsp;
        scored: <span id="scored-at"></span>
      </div>
    </div>
  </div>

  <!-- Recent transactions -->
  <div class="card">
    <h2>&#x1F4CB; Recent Transactions</h2>
    <div class="recent-list" id="recent"></div>
    <div class="build-info" style="margin-top:12px">
      build: {build_id} &nbsp;·&nbsp; commit: {commit_sha} &nbsp;·&nbsp;
      image: {image_tag}
    </div>
  </div>

</div>

<script>
const COLOURS = {{
  LOW:'#22c55e', MEDIUM:'#f59e0b', HIGH:'#f97316', CRITICAL:'#ef4444'
}};

async function loadRecent() {{
  const rows = await fetch('/recent').then(r=>r.json());
  const el = document.getElementById('recent');
  if (!rows.length) {{ el.innerHTML='<p style="color:#475569;font-size:13px;margin-top:8px">No transactions yet</p>'; return; }}
  el.innerHTML = rows.map(r=>`
    <div class="tx-row">
      <div>
        <div class="tx-id">${{r.transaction_id}}</div>
        <div style="font-size:11px;color:#475569;margin-top:2px">
          £${{r.amount || '—'}} · ${{r.scored_at.substring(11,19)}} UTC
        </div>
      </div>
      <span class="tx-pill" style="background:${{COLOURS[r.risk_level]}}22;
            color:${{COLOURS[r.risk_level]}};border:1px solid ${{COLOURS[r.risk_level]}}">
        ${{r.risk_level}} · ${{r.risk_score}}
      </span>
    </div>`).join('');
}}

document.getElementById('form').addEventListener('submit', async e => {{
  e.preventDefault();
  const body = {{
    amount_gbp: parseFloat(document.getElementById('amount').value),
    merchant_category: document.getElementById('category').value,
    country_code: document.getElementById('country').value,
    channel: document.getElementById('channel').value,
  }};
  const r = await fetch('/score', {{
    method:'POST', headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify(body)
  }}).then(x=>x.json());

  r.amount = body.amount_gbp;
  const c = COLOURS[r.risk_level];
  const res = document.getElementById('result');
  res.style.display='block'; res.style.borderColor=c; res.style.background=c+'11';
  document.getElementById('ring').style.color=c;
  document.getElementById('ring').textContent=r.risk_score;
  document.getElementById('level').style.color=c;
  document.getElementById('level').textContent=r.risk_level;
  document.getElementById('action-text').textContent=
    r.recommended_action==='BLOCK'  ? '🚫 Transaction Blocked' :
    r.recommended_action==='REVIEW' ? '⚠️ Flagged for Manual Review' :
                                      '✅ Approved for Processing';
  document.getElementById('factors').innerHTML=
    r.factors.map(f=>`<li>${{f}}</li>`).join('');
  document.getElementById('txn-id').textContent=r.transaction_id;
  document.getElementById('scored-at').textContent=r.scored_at.substring(0,19)+' UTC';
  loadRecent();
}});

loadRecent();
setInterval(loadRecent, 10000);
</script>
</body>
</html>"""

@app.get("/", response_class=HTMLResponse)
def index():
    return PAGE.format(
        build_id=BUILD_ID[:8],
        commit_sha=COMMIT_SHA[:8],
        image_tag=IMAGE_TAG[:12],
    )

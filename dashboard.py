import json
import re
from datetime import datetime
from collections import Counter
from pathlib import Path

COWRIE_LOG  = Path("logs/cowrie.json")
AGENT_LOG   = Path("logs/agent_session_day9.json")
OUTPUT_FILE = Path("logs/dashboard.html")


def parse_cowrie(path):
    if not path.exists():
        print(f"[!] Not found: {path}")
        return []
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def parse_agent(path):
    if not path.exists():
        print(f"[!] Not found: {path}")
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def build_data(events, agent_data):
    creds   = [e for e in events if e.get("eventid") in ("cowrie.login.failed", "cowrie.login.success")]
    conns   = [e for e in events if e.get("eventid") == "cowrie.session.connect"]
    success = [e for e in creds if e.get("eventid") == "cowrie.login.success"]

    tool_events = agent_data.get("tool_events", [])
    ssh_events  = [e for e in tool_events if e.get("event") == "ssh"]
    types       = {e.get("event") for e in tool_events}

    # Top credentials
    pair_counter = Counter(
        f"{e.get('username')}:{e.get('password')}" for e in creds
    )
    top_creds = [
        {"user": p.split(":")[0], "password": p.split(":")[1], "count": c}
        for p, c in pair_counter.most_common(8)
    ]

    # Top usernames
    user_counter = Counter(e.get("username", "") for e in creds)
    top_users = [{"name": u, "count": c} for u, c in user_counter.most_common(6)]

    # Top passwords
    pwd_counter = Counter(e.get("password", "") for e in creds)
    top_pwds = [{"name": p, "count": c} for p, c in pwd_counter.most_common(6)]

    # Top IPs
    ip_counter = Counter(e.get("src_ip") for e in conns if e.get("src_ip"))
    top_ips = [{"ip": ip, "count": c} for ip, c in ip_counter.most_common(5)]

    # Timeline — connexions par heure
    hourly = {}
    for e in conns:
        ts = e.get("timestamp", "")
        if len(ts) >= 13:
            hour = ts[:13].replace("T", " ") + ":00"
            hourly[hour] = hourly.get(hour, 0) + 1
    hourly_labels = sorted(hourly.keys())
    hourly_values = [hourly[k] for k in hourly_labels]

    # SSH timeline (agent)
    ssh_timeline = {}
    for e in ssh_events:
        ts = e.get("ts", "")
        if len(ts) >= 13:
            hour = ts[:13].replace("T", " ") + ":00"
            ssh_timeline[hour] = ssh_timeline.get(hour, 0) + 1
    ssh_labels = sorted(ssh_timeline.keys())
    ssh_values = [ssh_timeline[k] for k in ssh_labels]

    # Valid credentials
    valid_creds = list(set(
        f"{e.get('username')}:{e.get('password')}"
        for e in creds if e.get("eventid") == "cowrie.login.success"
    ))

    # MITRE techniques
    mitre = []
    if "nmap"   in types:
        mitre.append({"id": "T1046",    "name": "Network Service Discovery",           "tactic": "Discovery"})
    if "banner" in types:
        mitre.append({"id": "T1592.002","name": "Gather Victim Host Information",      "tactic": "Reconnaissance"})
    if "ssh"    in types:
        mitre.append({"id": "T1110.001","name": "Brute Force: Password Guessing",      "tactic": "Credential Access"})
    if any(e.get("eventid") == "cowrie.login.success" for e in events):
        mitre.append({"id": "T1078.001","name": "Valid Accounts: Default Accounts",    "tactic": "Initial Access"})
    if "http"   in types:
        mitre.append({"id": "T1595.003","name": "Active Scanning: Wordlist Scanning",  "tactic": "Reconnaissance"})
    if success:
        mitre.append({"id": "T1021.004","name": "Remote Services: SSH",                "tactic": "Lateral Movement"})

    # Agent SSH results
    ssh_results = {"success": 0, "failed": 0, "error": 0}
    for e in ssh_events:
        r = e.get("result", "")
        if r == "success":       ssh_results["success"] += 1
        elif r == "auth_failed": ssh_results["failed"]  += 1
        else:                    ssh_results["error"]   += 1

    return {
        "total_attempts"  : len(creds),
        "total_conns"     : len(conns),
        "unique_ips"      : len(ip_counter),
        "successes"       : len(success),
        "unique_creds"    : len(pair_counter),
        "top_creds"       : top_creds,
        "top_users"       : top_users,
        "top_pwds"        : top_pwds,
        "top_ips"         : top_ips,
        "hourly_labels"   : hourly_labels,
        "hourly_values"   : hourly_values,
        "ssh_labels"      : ssh_labels,
        "ssh_values"      : ssh_values,
        "valid_creds"     : valid_creds,
        "mitre"           : mitre,
        "ssh_results"     : ssh_results,
        "ai_summary"      : agent_data.get("ai_summary", "No summary available."),
        "target"          : agent_data.get("target", "N/A"),
        "generated_at"    : agent_data.get("generated_at", ""),
        "ssh_attempts"    : len(ssh_events),
    }


def generate_html(d):
    # Préparer les données JSON pour le JS
    hourly_labels  = json.dumps(d["hourly_labels"])
    hourly_values  = json.dumps(d["hourly_values"])
    ssh_labels     = json.dumps(d["ssh_labels"])
    ssh_values     = json.dumps(d["ssh_values"])
    top_ips_labels = json.dumps([x["ip"]   for x in d["top_ips"]])
    top_ips_values = json.dumps([x["count"] for x in d["top_ips"]])
    user_labels    = json.dumps([x["name"]  for x in d["top_users"]])
    user_values    = json.dumps([x["count"] for x in d["top_users"]])
    pwd_labels     = json.dumps([x["name"]  for x in d["top_pwds"]])
    pwd_values     = json.dumps([x["count"] for x in d["top_pwds"]])

    # Tableau credentials
    creds_rows = "".join(
        f'<tr><td>{c["user"]}</td><td class="td-highlight">{c["password"]}</td>'
        f'<td>{c["count"]}</td></tr>'
        for c in d["top_creds"]
    )

    # Tableau IPs
    ips_rows = "".join(
        f'<tr><td class="td-ip">{ip["ip"]}</td><td>{ip["count"]}</td>'
        f'<td><span class="badge">Malicious</span></td></tr>'
        for ip in d["top_ips"]
    )

    # Valid credentials badges
    valid_badges = "".join(
        f'<span class="badge-success">{c}</span>' for c in d["valid_creds"]
    ) or '<span class="td-muted">None detected</span>'

    # MITRE kill chain
    tactic_order  = ["Reconnaissance", "Discovery", "Credential Access", "Initial Access", "Lateral Movement"]
    tactic_config = {
        "Reconnaissance"  : ("🔍", "var(--accent-blue)",   "recon"),
        "Discovery"       : ("🗺️",  "var(--accent-cyan)",   "discovery"),
        "Credential Access": ("🔑", "var(--accent-yellow)", "credential"),
        "Initial Access"  : ("🚪", "var(--accent-purple)", "initial"),
        "Lateral Movement": ("⚡", "var(--accent-red)",    "lateral"),
    }

    grouped = {}
    for t in d["mitre"]:
        tac = t["tactic"]
        grouped.setdefault(tac, []).append(t)

    mitre_html = ""
    for tac in tactic_order:
        if tac not in grouped:
            continue
        icon, color, cls = tactic_config.get(tac, ("📌", "#fff", ""))
        mitre_html += f'<div class="tactic-group"><div class="tactic-header {cls}">{icon} {tac.upper()}</div>'
        for tech in grouped[tac]:
            mitre_html += (
                f'<div class="technique-card" style="color:{color}">'
                f'<div class="technique-id">{tech["id"]}</div>'
                f'<div class="technique-name" style="color:var(--text-main)">{tech["name"]}</div>'
                f'</div>'
            )
        mitre_html += '</div>'

    # SSH donut data
    ssh_donut_labels = json.dumps(["Success", "Failed", "Error"])
    ssh_donut_values = json.dumps([
        d["ssh_results"]["success"],
        d["ssh_results"]["failed"],
        d["ssh_results"]["error"],
    ])

    generated = datetime.now().strftime("%Y-%m-%d %H:%M")
    session_date = d["generated_at"][:10] if d["generated_at"] else "N/A"
    ai_summary = d["ai_summary"][:500] + ("..." if len(d["ai_summary"]) > 500 else "")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI-Augmented Honeypot | SOC Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  :root {{
    --bg-base    : #070b14;
    --bg-card    : #111827;
    --border     : #374151;
    --text-main  : #f3f4f6;
    --text-muted : #9ca3af;
    --accent-blue  : #3b82f6;
    --accent-cyan  : #06b6d4;
    --accent-green : #10b981;
    --accent-red   : #ef4444;
    --accent-yellow: #f59e0b;
    --accent-purple: #8b5cf6;
    --font-ui   : 'Inter', sans-serif;
    --font-mono : 'Fira Code', monospace;
  }}

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg-base);
    color: var(--text-main);
    font-family: var(--font-ui);
    font-size: 14px;
    line-height: 1.5;
    padding: 2rem;
    min-height: 100vh;
  }}

  header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid var(--border);
  }}

  h1 {{
    font-size: 1.4rem;
    font-weight: 700;
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }}

  h1::before {{
    content: '';
    display: inline-block;
    width: 11px;
    height: 11px;
    background: var(--accent-cyan);
    border-radius: 2px;
    box-shadow: 0 0 10px var(--accent-cyan);
  }}

  .header-meta {{
    font-family: var(--font-mono);
    font-size: 0.78rem;
    color: var(--text-muted);
    text-align: right;
    line-height: 1.8;
  }}

  .live-badge {{
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    font-family: var(--font-mono);
    font-size: 0.78rem;
    color: var(--accent-green);
    background: rgba(16,185,129,0.1);
    padding: 0.3rem 0.8rem;
    border-radius: 9999px;
    border: 1px solid rgba(16,185,129,0.25);
    margin-bottom: 6px;
  }}

  .pulse-dot {{
    width: 7px; height: 7px;
    background: var(--accent-green);
    border-radius: 50%;
    animation: pulse 2s infinite;
  }}

  @keyframes pulse {{
    0%   {{ box-shadow: 0 0 0 0 rgba(16,185,129,.7); }}
    70%  {{ box-shadow: 0 0 0 8px rgba(16,185,129,0); }}
    100% {{ box-shadow: 0 0 0 0 rgba(16,185,129,0); }}
  }}

  .grid {{ display: grid; gap: 1.25rem; }}
  .grid-4 {{ grid-template-columns: repeat(4,1fr); }}
  .grid-2 {{ grid-template-columns: repeat(2,1fr); }}
  .grid-3 {{ grid-template-columns: 2fr 1fr 1fr; }}

  .card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25rem 1.5rem;
    transition: border-color .2s;
  }}

  .card:hover {{ border-color: #4b5563; }}

  .card-label {{
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--text-muted);
    font-weight: 600;
    margin-bottom: 0.75rem;
  }}

  .kpi-value {{
    font-family: var(--font-mono);
    font-size: 2.2rem;
    font-weight: 600;
    line-height: 1;
  }}

  .kpi-sub {{
    font-size: 0.75rem;
    color: var(--text-muted);
    margin-top: 0.4rem;
    font-family: var(--font-mono);
  }}

  .c-cyan   {{ color: var(--accent-cyan); }}
  .c-purple {{ color: var(--accent-purple); }}
  .c-yellow {{ color: var(--accent-yellow); }}
  .c-red    {{ color: var(--accent-red); }}
  .c-green  {{ color: var(--accent-green); }}

  .chart-wrap {{ position: relative; height: 220px; }}

  .mitre-section {{
    border-left: 3px solid var(--accent-cyan);
  }}

  .kill-chain {{
    display: flex;
    gap: 1rem;
    overflow-x: auto;
    padding-bottom: 0.5rem;
  }}

  .tactic-group {{
    min-width: 210px;
    flex: 1;
    background: rgba(0,0,0,.2);
    border: 1px dashed var(--border);
    border-radius: 6px;
    padding: 1rem;
  }}

  .tactic-header {{
    font-size: 0.75rem;
    font-weight: 700;
    margin-bottom: 0.75rem;
    display: flex;
    align-items: center;
    gap: 0.4rem;
    letter-spacing: .05em;
  }}

  .tactic-header.recon      {{ color: var(--accent-blue); }}
  .tactic-header.discovery  {{ color: var(--accent-cyan); }}
  .tactic-header.credential {{ color: var(--accent-yellow); }}
  .tactic-header.initial    {{ color: var(--accent-purple); }}
  .tactic-header.lateral    {{ color: var(--accent-red); }}

  .technique-card {{
    background: var(--bg-base);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.6rem 0.75rem;
    margin-bottom: 0.4rem;
    position: relative;
    overflow: hidden;
  }}

  .technique-card::before {{
    content: '';
    position: absolute;
    left: 0; top: 0; bottom: 0;
    width: 3px;
    background: currentColor;
  }}

  .technique-id   {{ font-family: var(--font-mono); font-size: 0.7rem; color: var(--text-muted); margin-bottom: 2px; }}
  .technique-name {{ font-size: 0.8rem; font-weight: 600; color: var(--text-main); }}

  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th, td {{ padding: 0.65rem 0.75rem; border-bottom: 1px solid var(--border); text-align: left; }}
  th {{ font-size: 0.7rem; text-transform: uppercase; letter-spacing: .07em; color: var(--text-muted); background: rgba(255,255,255,.02); }}
  td {{ font-family: var(--font-mono); }}
  tr:last-child td {{ border-bottom: none; }}

  .td-highlight {{ color: var(--accent-yellow); }}
  .td-ip        {{ color: var(--accent-blue); }}
  .td-muted     {{ color: var(--text-muted); }}

  .badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.72rem;
    background: rgba(239,68,68,.1);
    color: var(--accent-red);
    border: 1px solid rgba(239,68,68,.2);
  }}

  .badge-success {{
    display: inline-block;
    font-family: var(--font-mono);
    font-size: 0.8rem;
    background: rgba(239,68,68,.12);
    color: var(--accent-red);
    border: 1px solid rgba(239,68,68,.25);
    padding: 3px 10px;
    border-radius: 5px;
    margin: 3px 4px 3px 0;
  }}

  .summary-box {{
    border-left: 3px solid var(--accent-green);
    padding: 0.75rem 1rem;
    background: rgba(16,185,129,.05);
    border-radius: 0 6px 6px 0;
    font-size: 0.85rem;
    color: #94a3b8;
    font-style: italic;
    line-height: 1.7;
  }}

  footer {{
    margin-top: 2rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
    font-family: var(--font-mono);
    font-size: 0.72rem;
    color: var(--text-muted);
    display: flex;
    justify-content: space-between;
  }}

  @media (max-width: 1024px) {{
    .grid-4 {{ grid-template-columns: repeat(2,1fr); }}
    .grid-2, .grid-3 {{ grid-template-columns: 1fr; }}
  }}
</style>
</head>
<body>

<header>
  <h1>AI-Augmented Honeypot</h1>
  <div class="header-meta">
    <div class="live-badge"><div class="pulse-dot"></div>Static Report — Real Data</div>
    <div>Target: <strong style="color:var(--text-main)">{d['target']}</strong></div>
    <div>Session: {session_date} &nbsp;|&nbsp; Generated: {generated}</div>
  </div>
</header>

<!-- KPIs -->
<div class="grid grid-4" style="margin-bottom:1.25rem">
  <div class="card">
    <div class="card-label">Total Attempts</div>
    <div class="kpi-value c-cyan">{d['total_attempts']}</div>
    <div class="kpi-sub">credential attempts captured</div>
  </div>
  <div class="card">
    <div class="card-label">Unique IPs</div>
    <div class="kpi-value c-purple">{d['unique_ips']}</div>
    <div class="kpi-sub">source addresses</div>
  </div>
  <div class="card">
    <div class="card-label">Unique Credentials</div>
    <div class="kpi-value c-yellow">{d['unique_creds']}</div>
    <div class="kpi-sub">distinct pairs tested</div>
  </div>
  <div class="card">
    <div class="card-label">Successful Logins</div>
    <div class="kpi-value c-red">{d['successes']}</div>
    <div class="kpi-sub">captured by Cowrie</div>
  </div>
</div>

<!-- Charts row 1 -->
<div class="grid grid-2" style="margin-bottom:1.25rem">
  <div class="card">
    <div class="card-label">Connection Timeline (Cowrie)</div>
    <div class="chart-wrap"><canvas id="timelineChart"></canvas></div>
  </div>
  <div class="card">
    <div class="card-label">Agent SSH Attempts</div>
    <div class="chart-wrap"><canvas id="sshChart"></canvas></div>
  </div>
</div>

<!-- Charts row 2 -->
<div class="grid grid-3" style="margin-bottom:1.25rem">
  <div class="card">
    <div class="card-label">Top Usernames</div>
    <div class="chart-wrap"><canvas id="userChart"></canvas></div>
  </div>
  <div class="card">
    <div class="card-label">Top Passwords</div>
    <div class="chart-wrap"><canvas id="pwdChart"></canvas></div>
  </div>
  <div class="card">
    <div class="card-label">SSH Results (Agent)</div>
    <div class="chart-wrap"><canvas id="sshDonut"></canvas></div>
  </div>
</div>

<!-- MITRE ATT&CK -->
<div class="card mitre-section" style="margin-bottom:1.25rem">
  <div class="card-label">MITRE ATT&CK — Detected Techniques</div>
  <div class="kill-chain">{mitre_html}</div>
</div>

<!-- Tables -->
<div class="grid grid-2" style="margin-bottom:1.25rem">
  <div class="card">
    <div class="card-label">Top Credentials Tested</div>
    <table>
      <thead><tr><th>Username</th><th>Password</th><th>Count</th></tr></thead>
      <tbody>{creds_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <div class="card-label">Top Source IPs</div>
    <table>
      <thead><tr><th>IP Address</th><th>Attempts</th><th>Status</th></tr></thead>
      <tbody>{ips_rows}</tbody>
    </table>
  </div>
</div>

<!-- Valid credentials -->
<div class="card" style="margin-bottom:1.25rem">
  <div class="card-label">Valid Credentials Captured</div>
  <div style="margin-top:4px">{valid_badges}</div>
</div>

<!-- AI Summary -->
<div class="card" style="margin-bottom:1.25rem">
  <div class="card-label">AI Agent Summary</div>
  <div class="summary-box">{ai_summary}</div>
</div>

<footer>
  <span>Abdellah Daoudi — ENSA El Jadida, ISIC Engineering</span>
  <span>LangChain + Ollama llama3.2:1b &nbsp;|&nbsp; Cowrie 2.x &nbsp;|&nbsp; Data: Real logs</span>
</footer>

<script>
Chart.defaults.color = '#9ca3af';
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.scale.grid.color = 'rgba(55,65,81,0.4)';

const COLORS = {{
  cyan  : 'rgba(6,182,212,',
  blue  : 'rgba(59,130,246,',
  yellow: 'rgba(245,158,11,',
  red   : 'rgba(239,68,68,',
  green : 'rgba(16,185,129,',
  purple: 'rgba(139,92,246,',
}};

function lineChart(id, labels, values, color) {{
  new Chart(document.getElementById(id), {{
    type: 'line',
    data: {{
      labels,
      datasets: [{{
        data: values,
        borderColor: color + '1)',
        backgroundColor: color + '0.08)',
        tension: 0.4,
        fill: true,
        pointRadius: 3,
        pointBackgroundColor: color + '1)',
      }}]
    }},
    options: {{
      responsive: true,
      maintainAspectRatio: false,
      plugins: {{ legend: {{ display: false }} }},
      scales: {{ y: {{ beginAtZero: true }} }}
    }}
  }});
}}

function barChart(id, labels, values, color, horizontal=false) {{
  new Chart(document.getElementById(id), {{
    type: 'bar',
    data: {{
      labels,
      datasets: [{{
        data: values,
        backgroundColor: color + '0.7)',
        borderRadius: 4,
      }}]
    }},
    options: {{
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: horizontal ? 'y' : 'x',
      plugins: {{ legend: {{ display: false }} }},
      scales: {{ x: {{ beginAtZero: true }}, y: {{ beginAtZero: true }} }}
    }}
  }});
}}

function donutChart(id, labels, values, colors) {{
  new Chart(document.getElementById(id), {{
    type: 'doughnut',
    data: {{
      labels,
      datasets: [{{ data: values, backgroundColor: colors, borderWidth: 0, hoverOffset: 4 }}]
    }},
    options: {{
      responsive: true,
      maintainAspectRatio: false,
      cutout: '65%',
      plugins: {{
        legend: {{
          position: 'bottom',
          labels: {{ font: {{ family: "'Fira Code'", size: 11 }}, padding: 12 }}
        }}
      }}
    }}
  }});
}}

// Render all charts
lineChart('timelineChart', {hourly_labels}, {hourly_values}, COLORS.cyan);
barChart('sshChart', {ssh_labels}, {ssh_values}, COLORS.red);
barChart('userChart', {user_labels}, {user_values}, COLORS.blue, true);
barChart('pwdChart', {pwd_labels}, {pwd_values}, COLORS.yellow, true);
donutChart('sshDonut',
  {ssh_donut_labels},
  {ssh_donut_values},
  ['#10b981', '#ef4444', '#9ca3af']
);
</script>
</body>
</html>"""


if __name__ == "__main__":
    print("[*] Parsing logs...")
    events     = parse_cowrie(COWRIE_LOG)
    agent_data = parse_agent(AGENT_LOG)

    if not events and not agent_data:
        print("[!] No data found. Check logs/ directory.")
        exit(1)

    data = build_data(events, agent_data)

    print(f"    {len(events)} events | {data['total_attempts']} attempts | {data['successes']} successes")
    print(f"    {len(data['mitre'])} MITRE techniques | {data['unique_ips']} unique IPs")

    html = generate_html(data)
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(html, encoding="utf-8")

    print(f"[*] Dashboard saved → {OUTPUT_FILE}")
    print(f"    Open with: firefox {OUTPUT_FILE}")

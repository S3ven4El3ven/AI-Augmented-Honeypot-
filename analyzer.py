import json
import re
from datetime import datetime
from collections import Counter
from pathlib import Path


COWRIE_LOG  = Path("logs/cowrie.json")
AGENT_LOG   = Path("logs/agent_session.json")
AGENT_V1    = Path("logs/agent_session_v1.json")
AGENT_V2    = Path("logs/agent_session_v2.json")
OUTPUT_FILE = Path("logs/analysis_notes.md")


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


def get_credentials(events):
    return [
        e for e in events
        if e.get("eventid") in ("cowrie.login.failed", "cowrie.login.success")
    ]


def get_connections(events):
    return [e for e in events if e.get("eventid") == "cowrie.session.connect"]


def credential_stats(creds):
    usernames = Counter(e.get("username", "") for e in creds)
    passwords = Counter(e.get("password", "") for e in creds)
    pairs     = Counter(f"{e.get('username')}:{e.get('password')}" for e in creds)
    successes = [e for e in creds if e.get("eventid") == "cowrie.login.success"]
    return {
        "total"           : len(creds),
        "unique_usernames": len(usernames),
        "unique_passwords": len(passwords),
        "top_usernames"   : usernames.most_common(5),
        "top_passwords"   : passwords.most_common(5),
        "top_pairs"       : pairs.most_common(5),
        "successes"       : successes,
    }


def build_timeline(connections, creds):
    if not connections:
        return {}

    def ts(e):
        return datetime.fromisoformat(e.get("timestamp", "").replace("Z", "+00:00"))

    try:
        times    = sorted(ts(e) for e in connections)
        duration = (times[-1] - times[0]).total_seconds()

        ctimes = sorted(ts(e) for e in creds)
        delays = [(ctimes[i] - ctimes[i-1]).total_seconds() for i in range(1, len(ctimes))]
        avg    = round(sum(delays) / len(delays), 2) if delays else 0

        return {
            "first"      : str(times[0]),
            "last"       : str(times[-1]),
            "duration_s" : round(duration, 2),
            "connections": len(connections),
            "avg_delay_s": avg,
        }
    except Exception as e:
        return {"error": str(e)}


def agent_stats(data):
    events = data.get("tool_events", [])
    ssh    = [e for e in events if e.get("event") == "ssh"]
    llm    = [e for e in events if e.get("event") == "llm_reasoning"]
    tried  = [(e.get("user"), e.get("pwd")) for e in ssh]
    return {
        "ssh_attempts" : len(ssh),
        "duplicates"   : len(tried) - len(set(tried)),
        "llm_steps"    : len(llm),
        "summary"      : data.get("ai_summary", "N/A"),
    }


def extract_iocs(events, agent_data):
    iocs = {"source_ips": [], "credentials": [], "sessions": [], "ports": [], "http_paths": []}

    iocs["source_ips"] = list(set(
        e.get("src_ip") for e in events
        if e.get("src_ip") and e.get("eventid") == "cowrie.session.connect"
    ))

    cred_events = get_credentials(events)
    iocs["credentials"] = list(set(
        f"{e.get('username')}:{e.get('password')}"
        for e in cred_events if e.get("username")
    ))

    iocs["sessions"] = list(set(e.get("session") for e in events if e.get("session")))

    tool_events = agent_data.get("tool_events", [])
    for e in [e for e in tool_events if e.get("event") == "nmap"]:
        iocs["ports"].extend(re.findall(r"port=(\d+)", e.get("result", "")))
    iocs["ports"] = list(set(iocs["ports"]))

    for e in [e for e in tool_events if e.get("event") == "http"]:
        url = e.get("url", "")
        if url:
            iocs["http_paths"].append("/" + "/".join(url.split("/")[3:]))

    return iocs


def credential_patterns(creds):
    default_pairs = {
        "root:root", "root:password", "root:123456", "root:toor", "root:alpine",
        "admin:admin", "admin:password", "admin:123456", "admin:admin123",
        "ubuntu:ubuntu", "pi:raspberry", "cowrie:cowrie",
        "user:user", "test:test", "guest:guest",
        "oracle:oracle", "postgres:postgres", "mysql:mysql",
    }
    service_users = {"pi", "cowrie", "ubuntu", "oracle", "postgres", "mysql", "vagrant"}
    username_counts = Counter(e.get("username", "") for e in creds)

    patterns = {"default": [], "weak": [], "numeric": [], "service": [], "reused_users": []}

    for e in creds:
        user = e.get("username", "")
        pwd  = e.get("password", "")
        pair = f"{user}:{pwd}"

        if pair in default_pairs:
            patterns["default"].append(pair)
        if pwd and len(pwd) < 6:
            patterns["weak"].append(pair)
        if pwd and pwd.isdigit():
            patterns["numeric"].append(pair)
        if user.lower() in service_users:
            patterns["service"].append(pair)

    patterns["reused_users"] = [u for u, c in username_counts.items() if c > 1]

    for k in ["default", "weak", "numeric", "service"]:
        patterns[k] = list(set(patterns[k]))

    return patterns


MITRE = {
    "nmap"    : ("T1046",    "Network Service Discovery",                "Discovery"),
    "banner"  : ("T1592.002","Gather Victim Host Information: Software", "Reconnaissance"),
    "ssh"     : ("T1110.001","Brute Force: Password Guessing",           "Credential Access"),
    "default" : ("T1078.001","Valid Accounts: Default Accounts",         "Initial Access"),
    "http"    : ("T1595.003","Active Scanning: Wordlist Scanning",       "Reconnaissance"),
    "success" : ("T1021.004","Remote Services: SSH",                     "Lateral Movement"),
}


def map_mitre(events, agent_data, patterns):
    tool_events = agent_data.get("tool_events", [])
    types       = {e.get("event") for e in tool_events}
    detected    = []

    checks = [
        ("nmap",    "nmap" in types,
         "nmap scan detected in agent log"),
        ("banner",  "banner" in types,
         "SSH banner grabbed on port 22"),
        ("ssh",     "ssh" in types,
         f"{len([e for e in tool_events if e.get('event')=='ssh'])} SSH attempts logged"),
        ("default", bool(patterns.get("default")),
         f"Default creds used: {', '.join(patterns.get('default', [])[:3])}"),
        ("http",    "http" in types,
         "HTTP paths probed"),
        ("success", any(e.get("eventid") == "cowrie.login.success" for e in events),
         f"{len([e for e in events if e.get('eventid')=='cowrie.login.success'])} successful logins in Cowrie"),
    ]

    for key, condition, evidence in checks:
        if condition:
            t = MITRE[key]
            detected.append({"id": t[0], "name": t[1], "tactic": t[2], "evidence": evidence})

    return detected


def compare_sessions(path1, path2):
    if not path1.exists() or not path2.exists():
        return {}

    def stats(data):
        events = data.get("tool_events", [])
        ssh    = [e for e in events if e.get("event") == "ssh"]
        return {
            "attempts" : len(ssh),
            "successes": len([e for e in ssh if e.get("result") == "success"]),
            "failures" : len([e for e in ssh if e.get("result") == "auth_failed"]),
            "unique"   : len(set(f"{e.get('user')}:{e.get('pwd')}" for e in ssh)),
            "summary"  : data.get("ai_summary", "N/A"),
        }

    d1 = json.loads(path1.read_text(encoding="utf-8"))
    d2 = json.loads(path2.read_text(encoding="utf-8"))
    s1 = stats(d1)
    s2 = stats(d2)

    return {
        "v1": s1,
        "v2": s2,
        "delta": {
            "attempts" : s2["attempts"]  - s1["attempts"],
            "successes": s2["successes"] - s1["successes"],
            "unique"   : s2["unique"]    - s1["unique"],
        },
    }


def write_report(stats, timeline, agent, iocs, patterns, mitre, comparison):
    lines = [
        "# AI-Augmented Honeypot — Analysis Report",
        f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "\n---\n",

        "## Credential Statistics\n",
        "| Metric | Value |",
        "|---|---|",
        f"| Total attempts | **{stats['total']}** |",
        f"| Unique usernames | {stats['unique_usernames']} |",
        f"| Unique passwords | {stats['unique_passwords']} |",
        f"| Successful logins | **{len(stats['successes'])}** |",
        "",
        "**Top usernames**",
        *[f"- `{u}` ({n})" for u, n in stats["top_usernames"]],
        "",
        "**Top passwords**",
        *[f"- `{p}` ({n})" for p, n in stats["top_passwords"]],
        "",
        "**Top pairs**",
        *[f"- `{pair}` ({n})" for pair, n in stats["top_pairs"]],

        "\n---\n",

        "## Attack Timeline\n",
        "| Metric | Value |",
        "|---|---|",
        f"| First connection | {timeline.get('first', 'N/A')} |",
        f"| Last connection | {timeline.get('last', 'N/A')} |",
        f"| Total duration | {timeline.get('duration_s', 0)}s |",
        f"| Total connections | {timeline.get('connections', 0)} |",
        f"| Avg delay between attempts | **{timeline.get('avg_delay_s', 0)}s** |",
        "",
        "> Reference: Hydra ~0.3s | This agent ~1–3s (LLM overhead)",

        "\n---\n",

        "## Agent Performance\n",
        "| Metric | Value |",
        "|---|---|",
        f"| SSH attempts | {agent['ssh_attempts']} |",
        f"| Duplicate credentials | {agent['duplicates']} |",
        f"| LLM reasoning steps | {agent['llm_steps']} |",
        "",
        "**AI Summary**",
        f"> {agent['summary']}",

        "\n---\n",

        "## IOC Extraction\n",
        "**Source IPs**",
        *[f"- `{ip}`" for ip in (iocs["source_ips"] or ["none"])],
        "",
        "**Unique credentials attempted**",
        *[f"- `{c}`" for c in sorted(iocs["credentials"])],
        "",
        "**Ports targeted**",
        *[f"- `{p}`" for p in sorted(iocs["ports"])],
        "",
        "**HTTP paths probed**",
        *[f"- `{p}`" for p in (iocs["http_paths"] or ["none"])],
        "",
        "**Sessions**",
        *[f"- `{s}`" for s in iocs["sessions"][:5]],

        "\n---\n",

        "## Credential Pattern Analysis\n",
        f"- Default credentials: **{len(patterns['default'])}** detected",
        *[f"  - `{c}`" for c in patterns["default"]],
        "",
        f"- Weak passwords (< 6 chars): {len(patterns['weak'])}",
        *[f"  - `{c}`" for c in patterns["weak"]],
        "",
        f"- Numeric-only passwords: {len(patterns['numeric'])}",
        *[f"  - `{c}`" for c in patterns["numeric"]],
        "",
        f"- Service-specific accounts: {len(patterns['service'])}",
        *[f"  - `{c}`" for c in patterns["service"]],

        "\n---\n",

        "## MITRE ATT&CK Mapping\n",
        "| ID | Technique | Tactic | Evidence |",
        "|---|---|---|---|",
        *[f"| `{t['id']}` | {t['name']} | {t['tactic']} | {t['evidence']} |" for t in mitre],
        "",
        "> https://attack.mitre.org",

        "\n---\n",

        "## Session Comparison\n",
        "| Metric | Initial Run | Optimized Run | Δ |",
        "|---|---|---|---|",
        f"| SSH attempts | {comparison.get('v1',{}).get('attempts',0)} | {comparison.get('v2',{}).get('attempts',0)} | +{comparison.get('delta',{}).get('attempts',0)} |",
        f"| Successes | {comparison.get('v1',{}).get('successes',0)} | {comparison.get('v2',{}).get('successes',0)} | +{comparison.get('delta',{}).get('successes',0)} |",
        f"| Unique credentials | {comparison.get('v1',{}).get('unique',0)} | {comparison.get('v2',{}).get('unique',0)} | +{comparison.get('delta',{}).get('unique',0)} |",
        f"| Failures | {comparison.get('v1',{}).get('failures',0)} | {comparison.get('v2',{}).get('failures',0)} | — |",
        "",
        "**Initial run summary**",
        f"> {comparison.get('v1',{}).get('summary','N/A')}",
        "",
        "**Optimized run summary**",
        f"> {comparison.get('v2',{}).get('summary','N/A')}",
    ]

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text("\n".join(lines), encoding="utf-8")
    print(f"[*] Report saved → {OUTPUT_FILE}")


if __name__ == "__main__":
    print("[*] Starting analysis...")
    Path("logs").mkdir(exist_ok=True)

    events      = parse_cowrie(COWRIE_LOG)
    creds       = get_credentials(events)
    connections = get_connections(events)
    print(f"    {len(events)} events | {len(creds)} credential attempts | {len(connections)} connections")

    stats    = credential_stats(creds)
    timeline = build_timeline(connections, creds)

    agent_data = parse_agent(AGENT_LOG)
    agent      = agent_stats(agent_data)

    iocs     = extract_iocs(events, agent_data)
    patterns = credential_patterns(creds)

    mitre = map_mitre(events, agent_data, patterns)
    for t in mitre:
        print(f"    [{t['id']}] {t['name']} ({t['tactic']})")

    comparison = compare_sessions(AGENT_V1, AGENT_V2)
    if comparison:
        print(f"    v1: {comparison['v1']['attempts']} attempts → v2: {comparison['v2']['attempts']} attempts")

    write_report(stats, timeline, agent, iocs, patterns, mitre, comparison)
    print("[*] Done.")

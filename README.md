# AI-Augmented Honeypot

A cybersecurity research project combining a Cowrie SSH honeypot with an AI-powered attack agent. The agent uses LangChain + Ollama (llama3.2:1b) to perform automated reconnaissance and credential attacks, while a separate analyzer processes the captured logs to extract IOCs and map techniques to MITRE ATT&CK.

---

## Architecture

```
┌─────────────────────────┐     Host-Only Network      ┌──────────────────────────┐
│      Kali Linux VM      │  ────────────────────────▶ │     Ubuntu 22.04 VM      │
│                         │     192.168.100.0/24        │                          │
│  agent.py               │                             │  Cowrie SSH Honeypot     │
│  ├── nmap scan          │  SSH brute-force + HTTP     │  ├── Port 22 (iptables)  │
│  ├── banner grab        │ ──────────────────────────▶ │  ├── Port 2222 (real)    │
│  ├── SSH brute-force    │                             │  └── cowrie.json logs    │
│  └── HTTP probe         │                             │                          │
│                         │ ◀──── cowrie.json ───────── │                          │
│  analyzer.py            │                             └──────────────────────────┘
│  ├── IOC extraction     │
│  ├── MITRE ATT&CK       │
│  └── session comparison │
│                         │
│  Ollama llama3.2:1b     │
└─────────────────────────┘
```

---

## Stack

| Component | Technology |
|---|---|
| Honeypot | Cowrie 2.x |
| Attacker OS | Kali Linux |
| Honeypot OS | Ubuntu 22.04 |
| AI Model | llama3.2:1b via Ollama |
| Agent Framework | LangChain + LangGraph |
| Network | VMware Host-Only (VMnet1) |
| Language | Python 3.10+ |

---

## Project Structure

```
ai-honeypot-project/
├── agent.py          # AI attack agent
├── analyzer.py       # Log analysis and threat intelligence
├── requirements.txt
├── README.md
└── logs/             # Generated at runtime (gitignored)
    ├── agent_session.json
    ├── cowrie.json
    └── analysis_notes.md
```

---

## Agent Pipeline

`agent.py` runs a 5-step automated attack:

```
1. nmap scan        →  identify open ports
2. banner grab      →  fingerprint running services
3. SSH brute-force  →  test 18 credential pairs, continues after success
4. HTTP probe       →  enumerate common web paths
5. session report   →  LLM generates summary, saves JSON log
```

The LLM analyzes results at each step and provides technical observations. Since llama3.2:1b does not support native tool-calling, the pipeline uses manual orchestration — Python controls the sequence, the LLM handles reasoning in plain text.

---

## Analyzer Modules

`analyzer.py` processes `cowrie.json` and `agent_session.json`:

| Module | Output |
|---|---|
| Credential stats | Top usernames, passwords, pairs |
| Session timeline | Duration, connection count, inter-attempt delay |
| Agent performance | Attempts, duplicates, LLM reasoning steps |
| IOC extraction | Source IPs, credentials, ports, HTTP paths, sessions |
| Credential patterns | Default creds, weak passwords, service accounts |
| MITRE ATT&CK mapping | Detected techniques with evidence |
| Session comparison | Initial run vs optimized run metrics |

---

## MITRE ATT&CK Coverage

| ID | Technique | Tactic |
|---|---|---|
| T1046 | Network Service Discovery | Discovery |
| T1592.002 | Gather Victim Host Information: Software | Reconnaissance |
| T1110.001 | Brute Force: Password Guessing | Credential Access |
| T1078.001 | Valid Accounts: Default Accounts | Initial Access |
| T1595.003 | Active Scanning: Wordlist Scanning | Reconnaissance |
| T1021.004 | Remote Services: SSH | Lateral Movement |

---

## Setup

### Ubuntu VM — Cowrie

```bash
# Install dependencies
sudo apt update && sudo apt install -y git python3-venv python3-dev \
  libssl-dev libffi-dev build-essential

# Create cowrie user
sudo adduser cowrie
sudo su - cowrie

# Create project folder and virtual environment
mkdir cowrie && cd cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install cowrie

# Create required directories
mkdir -p etc var/log/cowrie var/lib/cowrie

# Copy default config
cp cowrie-env/lib/python3.10/site-packages/cowrie/data/etc/cowrie.cfg.dist etc/cowrie.cfg

# Start Cowrie
cowrie-env/bin/cowrie start
cowrie-env/bin/cowrie status

# Redirect port 22 to Cowrie (run as root)
exit
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo apt install -y iptables-persistent && sudo netfilter-persistent save

# After running the agent, send logs to Kali
scp /home/cowrie/cowrie/var/log/cowrie/cowrie.json daoudi@192.168.100.20:/home/daoudi/ai_honeypot_project/logs/
```

### Kali VM — Agent

```bash
# Install Ollama and pull the model
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &
ollama pull llama3.2:1b

# Set up Python environment
python3 -m venv ~/ai_honeypot_env
source ~/ai_honeypot_env/bin/activate
pip install langchain langgraph langchain-ollama paramiko requests python-nmap

# Run the agent
mkdir -p ~/ai_honeypot_project/logs
cd ~/ai_honeypot_project
python3 agent.py

# After receiving cowrie.json from Ubuntu, run the analyzer
python3 analyzer.py
```

---

## Key Findings

- **llama3.2:1b** does not support native LangChain tool-calling — manual orchestration is required
- Cowrie successfully captured all attack attempts including credentials, banners, and session IDs
- The credential `root:password` was identified as valid by the agent and confirmed in Cowrie logs
- The agent's inter-attempt delay (~1.3s) is significantly higher than Hydra (~0.3s), making it detectable via timing analysis
- Default credentials accounted for the majority of attempts — highlighting poor default security practices
- The optimized run tested 18 credential pairs vs 5 in the initial run, demonstrating iterative improvement

---

## Disclaimer

This project targets a controlled honeypot in an isolated lab network. Do not use these tools against systems you do not own or have explicit permission to test.

---

**Abdellah Daoudi** — ENSA El Jadida, ISIC Engineering

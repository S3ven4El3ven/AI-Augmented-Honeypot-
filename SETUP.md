# Environment Setup Guide

This guide details the complete process for reproducing the isolated multi-node virtual lab environment for the AI-Augmented Honeypot project.

### Prerequisites
* **Hypervisor:** VMware Workstation or Player installed.
* **Network Configuration:** Host-Only network interface configured as **VMnet1** (No internet routing).
* **Hardware Requirement:** Host machine with sufficient VRAM to run a 9B parameter model smoothly.

---

## 🖥️ Node 1: Honeypot VM Setup (Ubuntu Server)

To ensure proper security isolation, Cowrie must run under a dedicated, non-privileged user account (`cowrie-user`). Because non-root users cannot bind to ports below 1024, we will use `iptables-legacy` to forward standard SSH traffic (Port 22) down to Cowrie (Port 2222).

### Step 1: Secure the Real Administrative SSH Daemon
Before deploying the honeypot on port 22, you must relocate your actual Ubuntu administrative SSH access to a custom port to prevent conflicts and accidental self-deception.

```bash
# Modify the default SSH configuration file to listen on port 2223
sudo nano /etc/ssh/sshd_config

# Restart the SSH service to apply changes
sudo systemctl restart sshd
sudo systemctl start sshd
```

### Step 2: Create a Dedicated Non-Root User
```bash
# Create a new service user account with a password login
sudo adduser cowrie
sudo passwd cowrie 
# Switch to the new isolated user environment
sudo su - cowrieuser
```

### Step 3: Clone Cowrie and Establish Python Virtual Environment
*(Ensure you are running these commands inside your active `cowrie` session)*

```bash
# Clone the official repository source
git clone https://github.com/cowrie/cowrie.git
cd cowrie

# Build and isolate the Python virtual environment
python3 -m venv env
source env/bin/activate

# Upgrade pip package installer and retrieve necessary dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Configure Native Port Forwarding
Because regular system users cannot bind directly to low-level socket ports, drop out of your `cowrieuser` session back to an administrative sudo user to implement network rules.

```bash
# Temporary exit back to your standard sudo account
exit

# Route incoming traffic from standard port 22 to Cowrie's listening port 2222 using iptables-legacy
sudo iptables-legacy -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# Verify the network rule was successfully committed to the NAT table architecture
sudo iptables-legacy -t nat -L
```

### Step 5: Launch the Honeypot System
Return to your isolated service account, reactivate the environment variables, and boot the daemon.

```bash
# Switch back to the service account
sudo su - cowrieuser
cd cowrie
source env/bin/activate

# Boot the honeypot application framework
cowrie start
```
---

## 🧠 Node 2: LLM Engine Host Setup (Windows / Host PC)

The LLM runs directly on the underlying host machine to leverage its local hardware GPU processing power.

1. Download and install the core framework executable from [Ollama's Official Site](https://ollama.com).
2. Launch your command prompt/terminal and pull down the designated model structure:
   ```cmd
   ollama pull qwen3.5:9b
   ```
3. To allow external requests coming from your guest virtual machines to connect seamlessly, update your system environment variables to let Ollama listen globally:
   * **Variable Name:** `OLLAMA_HOST`
   * **Value:** `0.0.0.0` or `0.0.0.0:11434`
4. Verify your local network adapter IP on the virtual space (**VMnet1** interface should reflect `192.168.100.1`)


---

# ⚔️ Node 3: Attacker Engine VM Setup (Kali Linux)

This node houses the baseline requirements to interface with both the LLM API on the host and the Honeypot target over the local network interface.

### Step 1: Establish Python Virtual Environment & Install Dependencies
Before running scripts, isolate your environment using a Python virtual environment and install the required core networking and framework libraries (`langgraph`, `langchain`, `paramiko`, etc.).

```bash
# Create a Python virtual environment named 'env'
python3 -m venv env

# Activate the virtual environment
source env/bin/activate

# Upgrade the pip package installer inside the environment
pip install --upgrade pip

# Install the fundamental core libraries directly
pip install langgraph langchain-core langchain-community paramiko nmap
```

### Step 2: Infrastructure Connection Verification
Before testing your code logic, explicitly verify that your Kali VM can communicate across the local network interface, bypass the Windows host firewall, and reach the LLM API endpoint.

```bash
# Test the connection to the local Ollama API endpoint using curl
curl http://192.168.100.1:11434/api/tags
```

### Step 3: Run the agent

```bash
# Campaign 1 (baseline)
python agent.py

# Campaign 2 (with credential dedup and prompt fixes)
python agent_v2.py
```

Logs are written to the `logs/` folder. Run the analyzers after each campaign:

```bash
python analyze_v1.py   # Campaign 1 stats
python analyze_v2.py   # Campaign 2 stats
python ioc_extract.py  # Extract IOCs from agent logs
```

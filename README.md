# AI-Powered Endpoint Detection & Triage Lab (Osquery + Ollama)

This project demonstrates a custom, lightweight Endpoint Detection and Response (EDR) solution built to run on a single Kali Linux VM. It uses **Osquery** as an endpoint sensor, a **Python** script as the detection engine, and a **locally-hosted LLM (Ollama)** to perform automated AI-powered triage of alerts.

This lab simulates how a modern Security Operations Center (SOC) can use open-source tools and local AI to detect and respond to threats on endpoint devices without relying on expensive cloud services.

### Core Technologies
* **Sensor (EDR):** `Osquery` (Industry-standard endpoint monitoring)
* **Detection Engine:** `Python 3` (Custom script to parse logs and apply logic)
* **AI Triage (SOAR):** `Ollama` (Running the `tinyllama` model locally)
* **Attack:** `Netcat` Bash Reverse Shell (MITRE ATT&CK T1059.004)
* **Environment:** `Kali Linux VM`

---

## 🚀 Project In Action

This screenshot captures the complete detection cycle:
1.  **(Bottom Center)** The attacker executes a reverse shell.
2.  **(Top Right)** The C2 listener receives the connection.
3.  **(Left)** The detection script, monitoring Osquery logs, **detects the malicious `bash` process's network connection**, fires a `HIGH SEVERITY ALERT`, and **sends it to the local AI for analysis**.
4.  The AI **provides an instant triage report**, identifying the attack, the MITRE Tactic, and the correct remediation step.

![DETECTION_IN_ACTION.png](Screenshot%20(290).png)

---

## 🛠️ How It Works

### 1. The Sensor: Osquery
I configured Osquery to run as a service, using a custom-written query to act as our primary detection rule. Instead of hunting for a specific `nc` command, my debugging revealed the attack *actually* creates a `bash` process.

This query runs every 30 seconds, hunting for the true indicator of a reverse shell: a `bash` process with an active outbound network connection.

**`osquery.conf`:**
```sql
-- This query is the core detection logic --
SELECT p.name, p.pid, p.cmdline, pos.remote_port 
FROM processes AS p 
JOIN process_open_sockets AS pos ON p.pid = pos.pid 
WHERE p.name = 'bash' AND pos.remote_port != 0 AND pos.family = 2;
```

### 2. The Detector: Python
A Python script runs as a service (sudo python3 detect_and_triage.py), continuously watching the Osquery log file (/var/log/osquery/osqueryd.results.log).

When the Osquery query above finds a match, it writes a log. The script immediately parses this log and flags it as a HIGH SEVERITY ALERT.

### 3. The AI Brain: Ollama + Python
Once an alert is confirmed, the script sends the JSON log entry to a locally-running Ollama server (listening on http://localhost:11434).

A custom prompt engineers the LLM to act as a "Senior SecOps Analyst," providing a concise, actionable triage report, including MITRE ATT&CK mapping and remediation steps.

**`detect_and_triage.py (AI Prompt)`:**
```python
-- This AI Prompt --
prompt = f"""
You are a senior SecOps threat analyst. I have a suspicious log entry
from Osquery. Our detection query found a 'bash' process with an active
outbound network connection, indicating a potential reverse shell.
Please provide a concise triage analysis.

- **Attack Analysis:** What specific attack is this log entry showing?
- **MITRE ATT&CK:** What is the Tactic and Technique ID? (e.g., T1059.004)
- **Remediation:** What is the *immediate* host-based remediation step?

Suspicious Osquery Log:
{json.dumps(log_entry, indent=2)}
"""
```

🔐 Project Files
* detect_and_triage.py: The main Python detection and triage script.

* osquery.conf: The Osquery configuration file containing the detection query.

* DETECTION_IN_ACTION.png: The final proof-of-concept screenshot.

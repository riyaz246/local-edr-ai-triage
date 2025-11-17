import json
import subprocess
import time
import requests
import os

# Define constants for clarity
OSQUERY_LOG = "/var/log/osquery/osqueryd.results.log"
OLLAMA_API = "http://localhost:11434/api/generate"
MODEL_NAME = "tinyllama" # The model you pulled

def analyze_with_llm(log_entry):
    """
    Sends the suspicious log to the local Ollama LLM for triage.
    """
    
    # This prompt is engineered to be specific for a SecOps analyst
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
    
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False  # Wait for the full response, don't stream it
    }
    
    try:
        # Set a timeout for the request
        response = requests.post(OLLAMA_API, json=payload, timeout=60)
        response.raise_for_status() # Raise an exception for bad status codes (like 404 or 500)
        
        print("\n" + "="*50)
        print("🚨 AI-POWERED TRIAGE ANALYSIS 🚨")
        print("="*50)
        
        # Parse the JSON response from Ollama
        ai_response = response.json().get('response', 'No response from AI.')
        print(ai_response.strip())
        
        print("="*50 + "\n")
        
    except requests.exceptions.RequestException as e:
        print(f"\n[!] CRITICAL ERROR: Could not contact Ollama API at {OLLAMA_API}.")
        print(f"    Details: {e}")
        print(f"    Please ensure 'ollama run {MODEL_NAME}' is running in a separate terminal.")

def detection_rule(log_data):
    """
    This is our NEW detection logic based on debugging.
    The Osquery query itself is the detection: it finds a 'bash' process
    with an outbound network connection.
    """
    
    # We are looking for the results of our scheduled query
    if not log_data or log_data.get('name') != 'suspicious_processes':
        return False

    # If we find a log, the query has found a match! This is the alert.
    print(f"\n[!!!] HIGH SEVERITY ALERT: Possible Bash Reverse Shell Detected!")
    
    columns = log_data.get('columns', {})
    print(f"      Process Name: {columns.get('name')}")
    print(f"      PID: {columns.get('pid')}")
    print(f"      Remote Port: {columns.get('remote_port')}")
    
    return True # Trigger the AI analysis

def watch_log():
    """
    Uses 'tail -f' to watch the Osquery log file in real-time
    and pipes the output to this script.
    """
    print(f"[*] Starting detector. Tailing Osquery log: {OSQUERY_LOG}")
    print("[*] Waiting for suspicious activity...")
    
    # We are running this whole script with 'sudo', so 'tail' has permission
    try:
        process = subprocess.Popen(['tail', '-f', '-n', '0', OSQUERY_LOG],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   text=True)
    except FileNotFoundError:
        print(f"[!] Error: 'tail' command not found.")
        return
    except Exception as e:
        print(f"[!] Error starting 'tail': {e}")
        return

    try:
        while True:
            line = process.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            try:
                # Each line in the log is a separate JSON object
                log_entry = json.loads(line)
                
                # Pass the log to our detection rule
                if detection_rule(log_entry):
                    # If the rule returns True, send to the AI
                    analyze_with_llm(log_entry)
                    
            except json.JSONDecodeError:
                # Ignore non-JSON lines or corrupted entries
                pass
            except Exception as e:
                print(f"[!] Error processing log line: {e}")

    except KeyboardInterrupt:
        print("\n[*] Stopping detector...")
        process.kill()
    
    finally:
        if process.poll() is None:
            process.kill()
        print("[*] Detector shut down.")

if __name__ == "__main__":
    # Check if the script is run as root
    if os.geteuid() != 0:
        print("[!] ERROR: This script must be run with sudo to access Osquery logs.")
        print("    Please run: sudo python3 detect_and_triage.py")
    else:
        watch_log()

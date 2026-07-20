import requests
import json
import datetime
import os
import getpass
import time

# Configuration
OLLAMA_URL = "http://localhost:11434/api/chat"
LOG_FILE = "alerts.json"
GUARD_MODEL = "llama-guard3"
CORE_MODEL = "llama3.2"

CURRENT_USER = getpass.getuser()
# Use a session for better connection pooling
session = requests.Session()

# Llama Guard 3 Taxonomy Mapping
TAXONOMY = {
    "S1": "Violent Crimes",
    "S2": "Non-Violent Crimes",
    "S3": "Sexually Explicit Content",
    "S4": "Child Safety",
    "S5": "Defamation",
    "S6": "Specialized Advice (Medical/Legal)",
    "S7": "Privacy Violations",
    "S8": "Intellectual Property",
    "S9": "Hate Speech",
    "S10": "Public Interest Topics",
    "S11": "Jailbreaking / AI Circumvention",
}

def log_to_wazuh(event_type, prompt, user, category_code="N/A", category_desc="N/A"):
    alert = {
        "timestamp": datetime.datetime.now().isoformat(),
        "integration": "llama_guard",
        "user_id": user,
        "event": event_type,
        "category_code": category_code,
        "category_name": category_desc,
        "prompt_snippet": prompt[:100],
        "status": "blocked" if event_type in ["POLICY_VIOLATION", "SYSTEM_ERROR"] else "allowed"
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")

def call_ollama(model, user_input):
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": user_input}],
        "stream": False,
        "options": {
            "num_thread": 8
        }
    }
    try:
        response = session.post(OLLAMA_URL, json=payload, timeout=120)
        
        if response.status_code != 200:
            print(f"DEBUG: Server returned {response.status_code}: {response.text}")
            return "error"
            
        data = response.json()
        return data.get('message', {}).get('content', "").strip()
    except Exception as e:
        print(f"CONNECTION ERROR: {e}")
        return "error"

def ask_ai(user_input):
    print(f"\n--- Processing: {user_input[:30]}... ---")
    
    # 1. Security Check
    print(f"Step 1: Shielding with {GUARD_MODEL}...")
    safety_result = call_ollama(GUARD_MODEL, user_input)
    
    if safety_result == "error":
        print("🔴 SYSTEM CRASH: Security model failed to respond.")
        log_to_wazuh("SYSTEM_ERROR", user_input, CURRENT_USER, "ERROR", "Ollama 500/Timeout")
        return "Access Blocked: Security engine failure."

    # Parsing Llama Guard output (Expects 'unsafe\nSxx' or 'safe')
    lines = safety_result.split('\n')
    verdict = lines[0].strip().lower()
    
    if "unsafe" in verdict:
        category_code = lines[1].strip() if len(lines) > 1 else "Unknown"
        category_desc = TAXONOMY.get(category_code, "Policy Violation")
        
        print(f"🔴 IDPS BLOCK: {category_desc} ({category_code})")
        log_to_wazuh("POLICY_VIOLATION", user_input, CURRENT_USER, category_code, category_desc)
        return f"Access Denied: Your prompt triggered a security policy ({category_desc})."
    
    # 2. Core AI
    print(f"✅ Step 2: Prompt is safe. Generating response with {CORE_MODEL}...")
    log_to_wazuh("CLEAN_PROMPT", user_input, CURRENT_USER)
    
    ai_response = call_ollama(CORE_MODEL, user_input)
    if ai_response == "error":
        return "Error: Core AI failed to generate a response."
        
    return f"\n[Llama 3.2]: {ai_response}"

if __name__ == "__main__":
    print(f"--- AI Security Lab Active (User: {CURRENT_USER}) ---")
    print("Logs are being saved to alerts.json for Wazuh monitoring.")
    while True:
        p = input("\nEnter Prompt: ")
        if p.lower() in ['exit', 'quit']: break
        if not p.strip(): continue
        print(ask_ai(p))
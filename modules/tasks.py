import json
import os
import subprocess
import uuid
from datetime import datetime

TASKS_FILE = "tasks.json"

def load_tasks():
    if os.path.exists(TASKS_FILE):
        with open(TASKS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_tasks(tasks):
    with open(TASKS_FILE, 'w') as f:
        json.dump(tasks, f, indent=4)

def run_scan_background(task_id, tool, profile, url, timeout):
    try:
        cmd = None
        if tool == "Nmap":
            if profile == "Básico":
                cmd = ["wsl", "sudo", "nmap", "-sV", url]
            elif profile == "Agresivo":
                cmd = ["wsl", "sudo", "nmap", "-A", url]
            elif profile == "Sigiloso":
                cmd = ["wsl", "sudo", "nmap", "-sS", "-sV", url]
            elif profile == "Ippsec":
                cmd = ["wsl", "sudo", "nmap", "-sC", "-sV", "-O", url]
            else:
                cmd = ["wsl", "sudo", "nmap", "-sV", url]  # default
        elif tool == "Nikto":
            if profile == "Básico":
                cmd = ["wsl", "nikto", "-h", url, "-Display", "V"]
            elif profile == "Completo":
                cmd = ["wsl", "nikto", "-h", url, "-C", "all", "-Display", "V"]
            else:
                cmd = ["wsl", "nikto", "-h", url, "-Display", "V"]  # default
        elif tool == "SQLMap":
            cmd = ["wsl", "python3", "~/sqlmap/sqlmap.py", "-u", url, "--batch"]
        elif tool == "Gobuster":
            cmd = ["wsl", "~/go/bin/gobuster", "dir", "-u", url, "-w", "~/common.txt"]
        elif tool == "Metasploit":
            cmd = ["wsl", "msfconsole", "-q", "-x", f"use auxiliary/scanner/http/http_version; set RHOSTS {url}; run; exit"]
        elif tool == "OWASP ZAP":
            cmd = ["wsl", "~/ZAP_2.15.0/zap.sh", "-cmd", "-quickurl", url]
        else:
            raise ValueError(f"Herramienta no soportada: {tool}")
        
        if cmd:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = result.stdout + result.stderr
            tasks = load_tasks()
            tasks[task_id]["status"] = "completed"
            tasks[task_id]["result"] = output
            save_tasks(tasks)
            
            # Save to history
            from modules.history import load_history, save_history
            history = load_history()
            history.append({
                "id": task_id,
                "timestamp": tasks[task_id]["start_time"],
                "prompt": f"Escaneo {tool} en {url} con perfil {profile}",
                "result": output,
                "provider": "Scan"
            })
            save_history(history)
            # Remove from tasks
            del tasks[task_id]
            save_tasks(tasks)
        else:
            raise ValueError(f"Perfil no soportado para {tool}: {profile}")
    except Exception as e:
        tasks = load_tasks()
        tasks[task_id]["status"] = "failed"
        tasks[task_id]["error"] = str(e)
        save_tasks(tasks)
        
        # Save to history
        from modules.history import load_history, save_history
        history = load_history()
        history.append({
            "id": task_id,
            "timestamp": tasks[task_id]["start_time"],
            "prompt": f"Escaneo {tool} en {url} con perfil {profile}",
            "result": f"Error: {str(e)}",
            "provider": "Scan"
        })
        save_history(history)
        # Remove from tasks
        del tasks[task_id]
        save_tasks(tasks)
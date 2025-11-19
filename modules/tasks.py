import json
import os
import subprocess
import platform
import shutil
import socket

TASKS_FILE = "tasks.json"

# Load sudo password based on hostname
hostname = socket.gethostname()
env_file = f".env.{hostname}"
sudo_password = None
if os.path.exists(env_file):
    with open(env_file, 'r') as f:
        for line in f:
            if line.startswith('SUDO_PASSWORD='):
                sudo_password = line.split('=', 1)[1].strip()
                break

TOOLS_PROFILES = {
    "Nmap": ["Básico", "Agresivo", "Sigiloso", "Ippsec", "All ports", "Deep info with service detection"],
    "Nikto": ["Básico", "Completo"],
    "SQLMap": ["Default"],
    "Gobuster": ["Default"],
    "Metasploit": ["Default", "Vuln Check Auto"],
    "OWASP ZAP": ["Default"]
}

# Map of services to Metasploit modules with check method
SERVICE_MODULES = {
    "http": ["auxiliary/scanner/http/http_version", "auxiliary/scanner/http/dir_scanner"],
    "https": ["auxiliary/scanner/http/http_version", "auxiliary/scanner/http/dir_scanner"],
    "ftp": ["auxiliary/scanner/ftp/ftp_version"],
    "ssh": ["auxiliary/scanner/ssh/ssh_version"],
    "smb": ["auxiliary/scanner/smb/smb_version"],
    "mysql": ["auxiliary/scanner/mysql/mysql_version"],
    "postgresql": ["auxiliary/scanner/postgres/postgres_version"],
    "rdp": ["auxiliary/scanner/rdp/rdp_scanner"],
    # Add more as needed
}

def run_cmd_with_sudo(cmd, password=None):
    """Run command, handling sudo with password if provided."""
    if 'sudo' in cmd:
        cmd = [c for c in cmd if c != 'sudo']
        if password:
            process = subprocess.Popen(['sudo', '-S'] + cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True, bufsize=1, universal_newlines=True)
            process.stdin.write(password + '\n')  # type: ignore
            process.stdin.close()  # type: ignore
        else:
            process = subprocess.Popen(['sudo'] + cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
    else:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
    return process

def wrap_cmd_with_wsl_if_needed(cmd):
    if platform.system() == 'Windows':
        # Check if the main command is available on host
        main_cmd = cmd[0] if cmd[0] != 'sudo' else cmd[1]
        if shutil.which(main_cmd) is None:
            return ['wsl'] + cmd
    return cmd

def run_scan_streaming(tool, profile, url, timeout, wordlist=None):
    try:
        if wordlist:
            wordlist = os.path.expanduser(wordlist)
        base_cmd = None
        if tool == "Nmap":
            if profile == "Básico":
                base_cmd = ["sudo", "nmap", "-sV", url]
            elif profile == "Agresivo":
                base_cmd = ["sudo", "nmap", "-A", url]
            elif profile == "Sigiloso":
                base_cmd = ["sudo", "nmap", "-sS", "-sV", url]
            elif profile == "Ippsec":
                base_cmd = ["sudo", "nmap", "-sC", "-sV", "-O", url]
            elif profile == "All ports":
                base_cmd = ["sudo", "nmap", "-p-", "-sV", url]
            elif profile == "Deep info with service detection":
                base_cmd = ["sudo", "nmap", "-sC", "-sV", "-O", "-A", "-p-", url]
            else:
                base_cmd = ["sudo", "nmap", "-sV", url]  # default
        elif tool == "Nikto":
            if profile == "Básico":
                base_cmd = ["nikto", "-h", url, "-Display", "V"]
            elif profile == "Completo":
                base_cmd = ["nikto", "-h", url, "-C", "all", "-Display", "V"]
            else:
                base_cmd = ["nikto", "-h", url, "-Display", "V"]  # default
        elif tool == "SQLMap":
            base_cmd = ["python3", "~/sqlmap/sqlmap.py", "-u", url, "--batch"]
        elif tool == "Gobuster":
            base_cmd = ["~/go/bin/gobuster", "dir", "-u", url, "-w", wordlist or "~/common.txt", "-b", "404,401"]
            if url.startswith("https://"):
                base_cmd.append("-k")
        elif tool == "Metasploit":
            if profile == "Vuln Check Auto":
                # Scan services with Nmap
                yield "Scanning services with Nmap...\n"
                nmap_cmd = ["sudo", "nmap", "-sV", url]
                nmap_cmd = [os.path.expanduser(p) for p in nmap_cmd]
                cmd = wrap_cmd_with_wsl_if_needed(nmap_cmd)
                process = run_cmd_with_sudo(cmd, sudo_password)
                nmap_output = ""
                try:
                    for line in iter(process.stdout.readline, ''):  # type: ignore
                        nmap_output += line
                        yield line
                    process.stdout.close()  # type: ignore
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    yield f"Nmap timeout after {timeout} seconds\n"
                
                # Parse services
                services = []
                for line in nmap_output.split('\n'):
                    if '/tcp' in line and 'open' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            port = parts[0].split('/')[0]
                            service = parts[2]
                            services.append((port, service))
                yield f"\nDetected services: {services}\n"
                
                # Get modules to check
                modules_to_check = set()
                for port, service in services:
                    if service in SERVICE_MODULES:
                        modules_to_check.update(SERVICE_MODULES[service])
                
                if not modules_to_check:
                    yield "No relevant modules found for detected services.\n"
                    return
                
                # Execute checks
                for module in modules_to_check:
                    if module.startswith("auxiliary"):
                        action = "run"
                    else:
                        action = "check"
                    yield f"\nRunning {action} on module: {module}\n"
                    msf_cmd = ["msfconsole", "-q", "-x", f"use {module}; set RHOSTS {url}; {action}; exit"]
                    msf_cmd = [os.path.expanduser(p) for p in msf_cmd]
                    cmd = wrap_cmd_with_wsl_if_needed(msf_cmd)
                    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    try:
                        for line in iter(process.stdout.readline, ''):  # type: ignore
                            yield line
                        process.stdout.close()  # type: ignore
                        process.wait(timeout=timeout)  # Use configurable timeout
                        if process.returncode != 0:
                            yield f"Module {module} {action} failed with code {process.returncode}\n"
                    except subprocess.TimeoutExpired:
                        process.kill()
                        yield f"Module {module} {action} timeout after {timeout} seconds\n"
                return
            else:
                base_cmd = ["msfconsole", "-q", "-x", f"use auxiliary/scanner/http/http_version; set RHOSTS {url}; run; exit"]
        elif tool == "OWASP ZAP":
            base_cmd = ["~/ZAP_2.15.0/zap.sh", "-cmd", "-quickurl", url]
        else:
            yield f"Error: Herramienta no soportada: {tool}\n"
            return
        
        if base_cmd:
            base_cmd = [os.path.expanduser(p) for p in base_cmd]
            cmd = wrap_cmd_with_wsl_if_needed(base_cmd)
            process = run_cmd_with_sudo(cmd, sudo_password)
            try:
                for line in iter(process.stdout.readline, ''):  # type: ignore
                    if line:
                        yield line
                process.stdout.close()  # type: ignore
                process.wait(timeout=timeout)
                if process.returncode != 0:
                    yield f"Command exited with code {process.returncode}\n"
            except subprocess.TimeoutExpired:
                process.kill()
                yield f"Timeout after {timeout} seconds\n"
        else:
            yield f"Error: Perfil no soportado para {tool}: {profile}\n"
    except Exception as e:
        yield f"Error: {str(e)}\n"

def load_tasks():
    if os.path.exists(TASKS_FILE):
        with open(TASKS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_tasks(tasks):
    with open(TASKS_FILE, 'w') as f:
        json.dump(tasks, f, indent=4)

def run_scan_background(task_id, tool, profile, url, timeout, wordlist=None):
    try:
        base_cmd = None
        if tool == "Nmap":
            if profile == "Básico":
                base_cmd = ["sudo", "nmap", "-sV", url]
            elif profile == "Agresivo":
                base_cmd = ["sudo", "nmap", "-A", url]
            elif profile == "Sigiloso":
                base_cmd = ["sudo", "nmap", "-sS", "-sV", url]
            elif profile == "Ippsec":
                base_cmd = ["sudo", "nmap", "-sC", "-sV", "-O", url]
            elif profile == "All ports":
                base_cmd = ["sudo", "nmap", "-p-", "-sV", url]
            elif profile == "Deep info with service detection":
                base_cmd = ["sudo", "nmap", "-sC", "-sV", "-O", "-A", "-p-", url]
            else:
                base_cmd = ["sudo", "nmap", "-sV", url]  # default
        elif tool == "Nikto":
            if profile == "Básico":
                base_cmd = ["nikto", "-h", url, "-Display", "V"]
            elif profile == "Completo":
                base_cmd = ["nikto", "-h", url, "-C", "all", "-Display", "V"]
            else:
                base_cmd = ["nikto", "-h", url, "-Display", "V"]  # default
        elif tool == "SQLMap":
            base_cmd = ["python3", "~/sqlmap/sqlmap.py", "-u", url, "--batch"]
        elif tool == "Gobuster":
            base_cmd = ["~/go/bin/gobuster", "dir", "-u", url, "-w", wordlist or "~/common.txt", "-b", "404,401"]
            if url.startswith("https://"):
                base_cmd.append("-k")
        elif tool == "Metasploit":
            if profile == "Vuln Check Auto":
                output_lines = []
                # Scan services with Nmap
                output_lines.append("Scanning services with Nmap...\n")
                nmap_cmd = ["sudo", "nmap", "-sV", url]
                nmap_cmd = [os.path.expanduser(p) for p in nmap_cmd]
                cmd = wrap_cmd_with_wsl_if_needed(nmap_cmd)
                process = run_cmd_with_sudo(cmd, sudo_password)
                nmap_output = ""
                try:
                    for line in iter(process.stdout.readline, ''):  # type: ignore
                        nmap_output += line
                        output_lines.append(line)
                        tasks = load_tasks()
                        tasks[task_id]["output"] = ''.join(output_lines)
                        save_tasks(tasks)
                    process.stdout.close()  # type: ignore
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    output_lines.append(f"Nmap timeout after {timeout} seconds\n")
                
                # Parse services
                services = []
                for line in nmap_output.split('\n'):
                    if '/tcp' in line and 'open' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            port = parts[0].split('/')[0]
                            service = parts[2]
                            services.append((port, service))
                output_lines.append(f"\nDetected services: {services}\n")
                
                # Get modules to check
                modules_to_check = set()
                for port, service in services:
                    if service in SERVICE_MODULES:
                        modules_to_check.update(SERVICE_MODULES[service])
                
                if not modules_to_check:
                    output_lines.append("No relevant modules found for detected services.\n")
                else:
                    # Execute checks
                    for module in modules_to_check:
                        if module.startswith("auxiliary"):
                            action = "run"
                        else:
                            action = "check"
                        output_lines.append(f"\nRunning {action} on module: {module}\n")
                        tasks = load_tasks()
                        tasks[task_id]["output"] = ''.join(output_lines)
                        save_tasks(tasks)
                        
                        msf_cmd = ["msfconsole", "-q", "-x", f"use {module}; set RHOSTS {url}; {action}; exit"]
                        msf_cmd = [os.path.expanduser(p) for p in msf_cmd]
                        cmd = wrap_cmd_with_wsl_if_needed(msf_cmd)
                        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                        try:
                            for line in iter(process.stdout.readline, ''):  # type: ignore
                                output_lines.append(line)
                                tasks = load_tasks()
                                tasks[task_id]["output"] = ''.join(output_lines)
                                save_tasks(tasks)
                            process.stdout.close()  # type: ignore
                            process.wait(timeout=timeout)  # Use configurable timeout
                            if process.returncode != 0:
                                output_lines.append(f"Module {module} {action} failed with code {process.returncode}\n")
                        except subprocess.TimeoutExpired:
                            process.kill()
                            output_lines.append(f"Module {module} {action} timeout after {timeout} seconds\n")
                
                output = ''.join(output_lines)
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
                return
            else:
                base_cmd = ["msfconsole", "-q", "-x", f"use auxiliary/scanner/http/http_version; set RHOSTS {url}; run; exit"]
        elif tool == "OWASP ZAP":
            base_cmd = ["~/ZAP_2.15.0/zap.sh", "-cmd", "-quickurl", url]
        else:
            raise ValueError(f"Herramienta no soportada: {tool}")
        
        if base_cmd:
            base_cmd = [os.path.expanduser(p) for p in base_cmd]
            cmd = wrap_cmd_with_wsl_if_needed(base_cmd)
            tasks = load_tasks()
            tasks[task_id]["output"] = ""
            save_tasks(tasks)
            
            process = run_cmd_with_sudo(cmd, sudo_password)
            output_lines = []
            try:
                for line in iter(process.stdout.readline, ''):  # type: ignore
                    if line:
                        output_lines.append(line)
                        tasks = load_tasks()
                        tasks[task_id]["output"] = ''.join(output_lines)
                        save_tasks(tasks)
                process.stdout.close()  # type: ignore
                process.wait(timeout=timeout)
                if process.returncode != 0:
                    output_lines.append(f"Command exited with code {process.returncode}\n")
            except subprocess.TimeoutExpired:
                process.kill()
                output_lines.append(f"Timeout after {timeout} seconds\n")
            
            output = ''.join(output_lines)
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
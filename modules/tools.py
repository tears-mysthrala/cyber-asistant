import subprocess

def run_tool(tool_name, args):
    if tool_name == "run_nmap":
        url = args.get("url", "")
        cmd = ["wsl", "sudo", "nmap", "-sC", "-sV", "-O", url]
    elif tool_name == "run_nikto":
        url = args.get("url", "")
        cmd = ["wsl", "nikto", "-h", url, "-Display", "V"]
    elif tool_name == "run_sqlmap":
        url = args.get("url", "")
        cmd = ["wsl", "python3", "~/sqlmap/sqlmap.py", "-u", url, "--batch"]
    elif tool_name == "run_gobuster":
        url = args.get("url", "")
        cmd = ["wsl", "~/go/bin/gobuster", "dir", "-u", url, "-w", "~/common.txt"]
    elif tool_name == "run_metasploit":
        url = args.get("url", "")
        cmd = ["wsl", "msfconsole", "-q", "-x", f"use auxiliary/scanner/http/http_version; set RHOSTS {url}; run; exit"]
    elif tool_name == "run_zap":
        url = args.get("url", "")
        cmd = ["wsl", "~/ZAP_2.15.0/zap.sh", "-cmd", "-quickurl", url]
    else:
        return "Herramienta no soportada"
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout + result.stderr
    except Exception as e:
        return f"Error ejecutando {tool_name}: {str(e)}"
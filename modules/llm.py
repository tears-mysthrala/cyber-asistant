import requests
import json
import re

def run_tool(tool_name, args):
    import subprocess
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

def query_provider(prompt, system_prompt, provider, settings):
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt}
    ]
    if provider == "Ollama":
        url = settings.get("ollama_url", "http://localhost:11434/api/chat")
        model = settings.get("ollama_model", "llama3.2")
        data = {
            "model": model,
            "messages": messages,
            "stream": False
        }
        response = requests.post(url, json=data)
        if response.status_code == 200:
            content = response.json()['message']['content']
            if "TOOL_CALL:" in content:
                # Parse tool call
                match = re.search(r"TOOL_CALL:\s*(\w+)\s*url=(\S+)", content)
                if match:
                    tool_name = match.group(1)
                    tool_url = match.group(2)
                    tool_result = run_tool(tool_name, {"url": tool_url})
                    # Second call with tool result
                    messages.append({"role": "assistant", "content": content})
                    messages.append({"role": "user", "content": f"Resultado de {tool_name}: {tool_result}"})
                    data2 = {
                        "model": model,
                        "messages": messages,
                        "stream": False
                    }
                    response2 = requests.post(url, json=data2)
                    if response2.status_code == 200:
                        return response2.json()['message']['content']
                    else:
                        return f"Error en segunda llamada: {response2.status_code} - {response2.text}"
            return content
        else:
            return f"Error: {response.status_code} - {response.text}"
    elif provider == "OpenAI":
        url = settings.get("openai_url", "https://api.openai.com/v1/chat/completions")
        api_key = settings.get("openai_key", "")
        model = settings.get("openai_model", "gpt-3.5-turbo")
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "run_nmap",
                    "description": "Ejecuta un escaneo Nmap en una URL para detectar puertos abiertos, servicios y OS",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "La URL a escanear"}
                        },
                        "required": ["url"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "run_nikto",
                    "description": "Ejecuta un escaneo Nikto en una URL para detectar vulnerabilidades web",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "La URL a escanear"}
                        },
                        "required": ["url"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "run_sqlmap",
                    "description": "Ejecuta SQLMap para detectar inyecciones SQL en una URL",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "La URL a escanear"}
                        },
                        "required": ["url"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "run_gobuster",
                    "description": "Ejecuta Gobuster para enumerar directorios en una URL",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "La URL a escanear"}
                        },
                        "required": ["url"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "run_metasploit",
                    "description": "Ejecuta un módulo básico de Metasploit para escanear una URL",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "La URL a escanear"}
                        },
                        "required": ["url"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "run_zap",
                    "description": "Ejecuta un escaneo rápido con OWASP ZAP en una URL",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "La URL a escanear"}
                        },
                        "required": ["url"]
                    }
                }
            }
        ]
        data = {
            "model": model,
            "messages": messages,
            "max_tokens": 1500,
            "tools": tools,
            "tool_choice": "auto"
        }
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            resp_json = response.json()
            message = resp_json['choices'][0]['message']
            if 'tool_calls' in message:
                for tool_call in message['tool_calls']:
                    tool_name = tool_call['function']['name']
                    args = json.loads(tool_call['function']['arguments'])
                    tool_result = run_tool(tool_name, args)
                    messages.append(message)
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call['id'],
                        "content": tool_result
                    })
                # Second call with tool results
                data2 = {
                    "model": model,
                    "messages": messages,
                    "max_tokens": 1500
                }
                response2 = requests.post(url, headers=headers, json=data2)
                if response2.status_code == 200:
                    return response2.json()['choices'][0]['message']['content']
                else:
                    return f"Error en segunda llamada: {response2.status_code} - {response2.text}"
            else:
                return message['content']
        else:
            return f"Error: {response.status_code} - {response.text}"
    return "Proveedor no soportado"
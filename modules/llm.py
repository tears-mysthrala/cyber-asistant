import requests
import json
import re
import threading
import time
from openai import OpenAI

# Global dict for background tool results
background_results = {}


def run_tool_sync(tool_name, args, task_id):
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
        cmd = [
            "wsl",
            "msfconsole",
            "-q",
            "-x",
            f"use auxiliary/scanner/http/http_version; set RHOSTS {url}; run; exit",
        ]
    elif tool_name == "run_zap":
        url = args.get("url", "")
        cmd = ["wsl", "~/ZAP_2.15.0/zap.sh", "-cmd", "-quickurl", url]
    else:
        background_results[task_id] = "Herramienta no soportada"
        return
    try:
        print(f"Ejecutando {tool_name} en background con ID {task_id}...")
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600
        )  # Increased timeout for background
        output = result.stdout + result.stderr
        background_results[task_id] = output
        print(
            f"Resultado guardado para {task_id}: {output[:200]}..."
        )  # Truncate for log
    except Exception as e:
        error_msg = f"Error ejecutando {tool_name}: {str(e)}"
        background_results[task_id] = error_msg
        print(f"Error en {task_id}: {error_msg}")


def get_background_result(task_id):
    print(f"Consultando resultado para ID {task_id}...")
    if task_id in background_results:
        result = background_results[task_id]
        print(f"Resultado encontrado para {task_id}: {result[:200]}...")
        return result
    else:
        msg = f"Resultado no disponible aún para ID: {task_id}. Espera más tiempo."
        print(msg)
        return msg


def run_tool(tool_name, args, background=False):
    if background:
        task_id = f"{tool_name}_{int(time.time())}"
        print(f"Lanzando {tool_name} en background con ID {task_id}...")
        threading.Thread(target=run_tool_sync, args=(tool_name, args, task_id)).start()
        return f"Ejecutando {tool_name} en background. ID: {task_id}. Usa get_background_result para obtener resultados."
    else:
        # Synchronous execution for fast tools (none currently)
        print(f"Ejecutando {tool_name} sincrónicamente...")
        return run_tool_sync(tool_name, args, None)


def query_provider(prompt, system_prompt, provider, settings):
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt},
    ]
    if provider == "Ollama":
        base_url = settings.get("ollama_url", "http://localhost:11434/v1").rstrip("/")
        api_key = "ollama"  # Dummy key for Ollama
        model = settings.get("ollama_model", "llama3.2:latest")
        client = OpenAI(base_url=base_url, api_key=api_key)
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "run_nmap",
                    "description": "Ejecuta un escaneo Nmap en una URL para detectar puertos abiertos, servicios y OS",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "La URL a escanear",
                            }
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "run_nikto",
                    "description": "Ejecuta un escaneo Nikto en una URL para detectar vulnerabilidades web",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "La URL a escanear",
                            }
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "run_sqlmap",
                    "description": "Ejecuta SQLMap para detectar inyecciones SQL en una URL",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "La URL a escanear",
                            }
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "run_gobuster",
                    "description": "Ejecuta Gobuster para enumerar directorios en una URL",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "La URL a escanear",
                            }
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "run_metasploit",
                    "description": "Ejecuta un módulo básico de Metasploit para escanear una URL",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "La URL a escanear",
                            }
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "run_zap",
                    "description": "Ejecuta un escaneo rápido con OWASP ZAP en una URL",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "La URL a escanear",
                            }
                        },
                        "required": ["url"],
                    },
                },
            },
        ]
        try:
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=1500,
                tools=tools,
                tool_choice="auto",
                timeout=300,
            )
            message = response.choices[0].message
            if hasattr(message, "tool_calls") and message.tool_calls:
                for tool_call in message.tool_calls:
                    tool_name = tool_call.function.name
                    args = json.loads(tool_call.function.arguments)
                    if tool_name == "get_background_result":
                        tool_result = get_background_result(args.get("task_id", ""))
                    else:
                        background = args.get(
                            "background", True
                        )  # Default to background for slow tools
                        tool_result = run_tool(tool_name, args, background=background)
                    messages.append(message)
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": tool_result,
                        }
                    )
                # Second call with tool results
                response2 = client.chat.completions.create(
                    model=model, messages=messages, max_tokens=1500, timeout=300
                )
                return response2.choices[0].message.content
            else:
                return message.content
        except Exception as e:
            return f"Error con Ollama: {str(e)}"
    elif provider == "OpenAI":
        url = settings.get("openai_url", "https://api.openai.com/v1/chat/completions")
        api_key = settings.get("openai_key", "")
        model = settings.get("openai_model", "gpt-3.5-turbo")
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "run_nmap",
                    "description": "Ejecuta un escaneo Nmap en una URL para detectar puertos abiertos, servicios y OS (puede ser lento, ejecuta en background)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "La URL a escanear",
                            },
                            "background": {
                                "type": "boolean",
                                "description": "Ejecutar en background si es lento",
                                "default": True,
                            },
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "run_nikto",
                    "description": "Ejecuta un escaneo Nikto en una URL para detectar vulnerabilidades web (puede ser lento, ejecuta en background)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "La URL a escanear",
                            },
                            "background": {
                                "type": "boolean",
                                "description": "Ejecutar en background si es lento",
                                "default": True,
                            },
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "run_sqlmap",
                    "description": "Ejecuta SQLMap para detectar inyecciones SQL en una URL (muy lento, ejecuta en background)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "La URL a escanear",
                            },
                            "background": {
                                "type": "boolean",
                                "description": "Ejecutar en background",
                                "default": True,
                            },
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "run_gobuster",
                    "description": "Ejecuta Gobuster para enumerar directorios en una URL (puede ser lento, ejecuta en background)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "La URL a escanear",
                            },
                            "background": {
                                "type": "boolean",
                                "description": "Ejecutar en background si es lento",
                                "default": True,
                            },
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "run_metasploit",
                    "description": "Ejecuta un módulo básico de Metasploit para escanear una URL (puede ser lento, ejecuta en background)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "La URL a escanear",
                            },
                            "background": {
                                "type": "boolean",
                                "description": "Ejecutar en background si es lento",
                                "default": True,
                            },
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "run_zap",
                    "description": "Ejecuta un escaneo rápido con OWASP ZAP en una URL (muy lento, ejecuta en background)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "La URL a escanear",
                            },
                            "background": {
                                "type": "boolean",
                                "description": "Ejecutar en background",
                                "default": True,
                            },
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_background_result",
                    "description": "Obtiene el resultado de una tarea ejecutada en background usando su ID",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "task_id": {
                                "type": "string",
                                "description": "El ID de la tarea en background",
                            }
                        },
                        "required": ["task_id"],
                    },
                },
            },
        ]
        data = {
            "model": model,
            "messages": messages,
            "max_tokens": 1500,
            "tools": tools,
            "tool_choice": "auto",
        }
        response = requests.post(url, headers=headers, json=data, timeout=600)
        if response.status_code == 200:
            resp_json = response.json()
            message = resp_json["choices"][0]["message"]
            if "tool_calls" in message:
                for tool_call in message["tool_calls"]:
                    tool_name = tool_call["function"]["name"]
                    args = json.loads(tool_call["function"]["arguments"])
                    if tool_name == "get_background_result":
                        tool_result = get_background_result(args.get("task_id", ""))
                    else:
                        background = args.get(
                            "background", True
                        )  # Default to background for slow tools
                        tool_result = run_tool(tool_name, args, background=background)
                    messages.append(message)
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_call["id"],
                            "content": tool_result,
                        }
                    )
                # Second call with tool results
                data2 = {"model": model, "messages": messages, "max_tokens": 1500}
                response2 = requests.post(url, headers=headers, json=data2, timeout=600)
                if response2.status_code == 200:
                    try:
                        return response2.json()["choices"][0]["message"]["content"]
                    except json.JSONDecodeError:
                        return f"Error en segunda llamada: Respuesta no es JSON válido. Respuesta: {response2.text}"
                else:
                    return f"Error en segunda llamada: {response2.status_code} - {response2.text}"
            else:
                return message["content"]
        else:
            return f"Error: {response.status_code} - {response.text}"
    return "Proveedor no soportado"

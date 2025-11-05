import streamlit as st
import requests
import json
import os
import subprocess
import uuid
from datetime import datetime

HISTORY_FILE = "history.json"

def load_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r') as f:
            return json.load(f)
    return []

def save_history(history):
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=4)

def query_provider(prompt, system_prompt, provider, settings):
    if provider == "Ollama":
        url = settings.get("ollama_url", "http://localhost:11434/api/chat")
        model = settings.get("ollama_model", "llama3.2")
        data = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "stream": False
        }
        response = requests.post(url, json=data)
        if response.status_code == 200:
            return response.json()['message']['content']
        else:
            return f"Error: {response.status_code} - {response.text}"
    elif provider == "OpenAI":
        url = settings.get("openai_url", "https://api.openai.com/v1/chat/completions")
        api_key = settings.get("openai_key", "")
        model = settings.get("openai_model", "gpt-3.5-turbo")
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        data = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 1500
        }
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            return response.json()['choices'][0]['message']['content']
        else:
            return f"Error: {response.status_code} - {response.text}"
    return "Proveedor no soportado"

st.title("🛡️ Asistente para Auditorías de Ciberseguridad")

# Settings in sidebar
st.sidebar.header("Configuración")
provider = st.sidebar.selectbox("Proveedor", ["Ollama", "OpenAI"])
settings = {}
if provider == "Ollama":
    settings["ollama_url"] = st.sidebar.text_input("URL de Ollama", "http://localhost:11434/api/chat")
    settings["ollama_model"] = st.sidebar.text_input("Modelo", "llama3.2")
elif provider == "OpenAI":
    settings["openai_key"] = st.sidebar.text_input("API Key", type="password")
    settings["openai_url"] = st.sidebar.text_input("URL", "https://api.openai.com/v1/chat/completions")
    settings["openai_model"] = st.sidebar.text_input("Modelo", "gpt-3.5-turbo")

# Tabs
tab1, tab2, tab3 = st.tabs(["Auditoría", "Histórico", "Escaneo Activo"])

with tab1:
    # Sidebar para uploads
    uploaded_files = st.sidebar.file_uploader("Sube logs, PDFs o código para analizar", type=['txt', 'pdf', 'py'], accept_multiple_files=True)
    file_content = ""
    if uploaded_files:
        for uploaded_file in uploaded_files:
            if uploaded_file.type == 'text/plain':
                file_content += f"\n--- {uploaded_file.name} ---\n" + uploaded_file.read().decode('utf-8')
            else:
                file_content += f"\n--- {uploaded_file.name} --- (contenido no procesado para texto)"
        if not file_content.strip():
            file_content = "Archivos subidos: " + ", ".join([f.name for f in uploaded_files])

    # Input del usuario
    escenario = st.text_area("Describe el escenario de auditoría (e.g., 'Analiza este log por inyecciones SQL')")
    if st.button("¡Audita ya! 🚀"):
        if uploaded_files or escenario:
            prompt = f"Analiza: {escenario}\nContenido: {file_content[:5000]}"
            system_prompt = "Eres un experto en auditorías de ciberseguridad. Responde de forma estructurada: Hallazgos, Evidencias, Mitigaciones."
        with st.spinner(f"{provider} está auditando..."):
            resultado = query_provider(prompt, system_prompt, provider, settings)
        st.markdown("### Resultados de la Auditoría")
        st.write(resultado)
        # Save to history
        history = load_history()
        history.append({
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "prompt": prompt,
            "result": resultado,
            "provider": provider
        })
        save_history(history)
    else:
        st.warning("Sube archivos o describe un escenario para empezar.")

with tab2:
    history = load_history()
    if history:
        for i, entry in enumerate(reversed(history)):
            with st.expander(f"Sesión {len(history)-i}: {entry['timestamp'][:19]} - {entry['provider']} (ID: {entry.get('id', 'N/A')})"):
                st.write(f"**Prompt:** {entry['prompt']}")
                st.write(f"**Resultado:** {entry['result']}")
    else:
        st.write("No hay sesiones previas.")

with tab3:
    url = st.text_input("URL del endpoint a escanear (e.g., http://example.com)")
    tool = st.selectbox("Herramienta", ["Nmap", "Nikto", "SQLMap", "Gobuster", "Metasploit", "OWASP ZAP"])
    profile = st.selectbox("Perfil de escaneo", ["Básico", "Agresivo", "Sigiloso", "Ippsec"] if tool == "Nmap" else ["Básico", "Completo"])
    timeout = st.slider("Timeout (segundos)", 60, 600, 120)
    if st.button("Ejecutar Escaneo"):
        if url:
            with st.spinner("Ejecutando escaneo..."):
                if tool == "Nmap":
                    if profile == "Básico":
                        cmd = ["wsl", "nmap", "-sV", url]
                    elif profile == "Agresivo":
                        cmd = ["wsl", "nmap", "-A", url]
                    elif profile == "Sigiloso":
                        cmd = ["wsl", "nmap", "-sS", "-sV", url]
                    elif profile == "Ippsec":
                        cmd = ["wsl", "sudo", "nmap", "-sC", "-sV", "-O", url]
                elif tool == "Nikto":
                    if profile == "Básico":
                        cmd = ["wsl", "nikto", "-h", url, "-Display", "V"]
                    elif profile == "Completo":
                        cmd = ["wsl", "nikto", "-h", url, "-C", "all", "-Display", "V"]
                elif tool == "SQLMap":
                    cmd = ["wsl", "python3", "~/sqlmap/sqlmap.py", "-u", url, "--batch"]
                elif tool == "Gobuster":
                    cmd = ["wsl", "~/go/bin/gobuster", "dir", "-u", url, "-w", "~/common.txt"]
                elif tool == "Metasploit":
                    cmd = ["wsl", "msfconsole", "-q", "-x", f"use auxiliary/scanner/http/http_version; set RHOSTS {url}; run; exit"]
                elif tool == "OWASP ZAP":
                    cmd = ["wsl", "~/ZAP_2.15.0/zap.sh", "-cmd", "-quickurl", url]
                try:
                    if 'cmd' in locals():
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout) # pyright: ignore[reportPossiblyUnboundVariable]
                        output = result.stdout + result.stderr
                        st.session_state.last_scan_output = output
                        st.session_state.last_tool = tool
                        st.session_state.last_profile = profile
                        st.session_state.last_url = url
                        st.code(output)
                        if result.returncode == 0:
                            # Save scan to history
                            history = load_history()
                            history.append({
                                "id": str(uuid.uuid4()),
                                "timestamp": datetime.now().isoformat(),
                                "prompt": f"Escaneo {tool} {profile} en {url}",
                                "result": output,
                                "provider": "Scan"
                            })
                            save_history(history)
                    else:
                        st.error("Herramienta no soportada.")
                except subprocess.TimeoutExpired:
                    st.error("Escaneo timeout.")
                except FileNotFoundError:
                    st.error("Herramienta no encontrada. Asegúrate de que esté instalada en WSL.")
        else:
            st.warning("Ingresa una URL.")

    # Always show last scan if exists
    if 'last_scan_output' in st.session_state:
        st.markdown("### Último Escaneo")
        st.code(st.session_state.last_scan_output)
        # Option to analyze
        if st.button("Analizar con LLM"):
            output = st.session_state.last_scan_output
            tool = st.session_state.last_tool
            profile = st.session_state.last_profile
            url = st.session_state.last_url
            prompt = f"Analiza estos resultados de escaneo con {tool} ({profile}) para el endpoint {url}:\n{output[:5000]}"
            system_prompt = "Eres un experto en auditorías de ciberseguridad. Responde de forma estructurada: Hallazgos, Evidencias, Mitigaciones."
            with st.spinner(f"{provider} analizando..."):
                analysis = query_provider(prompt, system_prompt, provider, settings)
            st.markdown("### Análisis del Escaneo")
            st.write(analysis)
            # Save analysis to history
            history = load_history()
            history.append({
                "id": str(uuid.uuid4()),
                "timestamp": datetime.now().isoformat(),
                "prompt": prompt,
                "result": analysis,
                "provider": provider
            })
            save_history(history)
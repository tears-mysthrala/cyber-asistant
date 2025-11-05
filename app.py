from flask import Flask, render_template, request, redirect, url_for, flash, session
import json
import os
from datetime import datetime
import uuid
import threading

from modules.llm import query_provider
from modules.history import load_history, save_history
from modules.tasks import load_tasks, save_tasks, run_scan_background

app = Flask(__name__)
app.secret_key = 'cyber_assistant_secret'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/audit', methods=['GET', 'POST'])
def audit():
    if request.method == 'POST':
        selected_ids = request.form.getlist('selected_ids')
        if selected_ids:
            # Combined report
            history = load_history()
            selected_entries = [h for h in history if h['id'] in selected_ids]
            combined_results = "\n\n".join([f"ID {h['id']}: {h['result']}" for h in selected_entries])
            prompt = f"Genera un reporte combinado de los siguientes resultados de auditorías:\n{combined_results}"
            system_prompt = "Eres un experto en auditorías de ciberseguridad. Analiza los resultados combinados y proporciona un reporte consolidado con hallazgos, evidencias y mitigaciones."
        else:
            escenario = request.form.get('escenario', '')
            files = request.files.getlist('files')
            file_content = ""
            for file in files:
                if file and file.filename:
                    content = file.read().decode('utf-8')
                    file_content += f"\n--- {file.filename} ---\n{content}"
            
            if escenario or file_content:
                prompt = f"Analiza: {escenario}\nContenido: {file_content[:5000]}"
                system_prompt = "Eres un experto en auditorías de ciberseguridad. Siempre ejecuta escaneos en tiempo real usando herramientas, no uses información histórica o previa. Responde de forma estructurada: Hallazgos, Evidencias, Mitigaciones."
            else:
                return render_template('audit.html')
        
        provider = session.get('provider', 'Ollama')
        settings = session.get('settings', {})
        resultado = query_provider(prompt, system_prompt, provider, settings)
        
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
        
        return render_template('audit.html', result=resultado)
    
    return render_template('audit.html')

@app.route('/history')
def history():
    history_data = load_history()
    
    # Filters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    sort_order = request.args.get('sort', 'desc')
    keyword = request.args.get('keyword', '').lower()
    provider_filter = request.args.get('provider')
    
    # Filter by date
    if start_date:
        start_dt = datetime.fromisoformat(start_date)
        history_data = [h for h in history_data if datetime.fromisoformat(h['timestamp']) >= start_dt]
    if end_date:
        end_dt = datetime.fromisoformat(end_date)
        history_data = [h for h in history_data if datetime.fromisoformat(h['timestamp']) <= end_dt]
    
    # Filter by provider
    if provider_filter:
        history_data = [h for h in history_data if h.get('provider') == provider_filter]
    
    # Filter by keyword
    if keyword:
        history_data = [h for h in history_data if keyword in h.get('prompt', '').lower() or keyword in h.get('result', '').lower()]
    
    # Sort by timestamp
    history_data.sort(key=lambda x: x['timestamp'], reverse=(sort_order == 'desc'))
    
    return render_template('history.html', history=history_data, start_date=start_date, end_date=end_date, sort=sort_order, keyword=keyword, provider=provider_filter)

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        url = request.form.get('url')
        tool = request.form.get('tool')
        profile = request.form.get('profile')
        timeout = int(request.form.get('timeout', 120))
        background = 'background' in request.form
        
        provider = session.get('provider', 'Ollama')
        settings = session.get('settings', {})
        
        if background:
            task_id = str(uuid.uuid4())
            tasks = load_tasks()
            tasks[task_id] = {"status": "running", "tool": tool, "profile": profile, "url": url, "start_time": datetime.now().isoformat()}
            save_tasks(tasks)
            threading.Thread(target=run_scan_background, args=(task_id, tool, profile, url, timeout)).start()
            flash(f"Tarea iniciada en background. ID: {task_id}")
            return redirect(url_for('scan'))
        else:
            # Similar to before, but simplified
            flash("Escaneo sincrónico no implementado aún.")
            return redirect(url_for('scan'))
    
    return render_template('scan.html')

@app.route('/tasks')
def tasks():
    tasks_data = load_tasks()
    return render_template('tasks.html', tasks=tasks_data)

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'POST':
        provider = request.form.get('provider')
        session['provider'] = provider
        settings = {}
        if provider == 'Ollama':
            settings['ollama_url'] = request.form.get('ollama_url', 'http://localhost:11434/api/chat')
            settings['ollama_model'] = request.form.get('ollama_model', 'llama3.2')
        elif provider == 'OpenAI':
            settings['openai_key'] = request.form.get('openai_key')
            settings['openai_url'] = request.form.get('openai_url', 'https://api.openai.com/v1/chat/completions')
            settings['openai_model'] = request.form.get('openai_model', 'gpt-3.5-turbo')
        session['settings'] = settings
        session['dark_mode'] = 'dark_mode' in request.form
        flash('Configuración guardada.')
        return redirect(url_for('settings'))
    
    return render_template('settings.html')

if __name__ == '__main__':
    app.run(debug=True)
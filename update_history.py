import json
import uuid
import os

file_path = 'history.json'
if os.path.exists(file_path):
    with open(file_path, 'r') as f:
        history = json.load(f)
    
    for entry in history:
        if 'id' not in entry:
            entry['id'] = str(uuid.uuid4())
        if 'prompt' in entry and len(entry['prompt']) > 500:
            entry['prompt'] = entry['prompt'][:500] + '... (truncated)'
    
    with open(file_path, 'w') as f:
        json.dump(history, f, indent=4)
    print('Updated history.json')
else:
    print('File not found')
from flask import Flask, jsonify, render_template
from flask_cors import CORS
import os
import json
import logging
import threading
import time
import subprocess


app = Flask(__name__)
CORS(app)

CONTROLLER_LOG_FILE = os.path.expanduser('/home/zandar/pox/pox/controller.log') #you change this accordingly!
COWRIE_LOG_FILE = os.path.expanduser('/home/cowrie/cowrie/var/log/cowrie/cowrie.json') #same here!


def get_controller_logs():
    try:
        if not os.path.exists(CONTROLLER_LOG_FILE):
            return ["Controller log file not found. Is POX running?"]
        with open(CONTROLLER_LOG_FILE, 'r') as f:
            return [line.strip() for line in f.readlines()[-30:]]
    except Exception as e:
        return [f"Error reading controller log: {str(e)}"]

def get_cowrie_logs():
    try:
        if not os.path.exists(COWRIE_LOG_FILE):
            return []
        
        events = []
        with open(COWRIE_LOG_FILE, 'r') as f:
            log_lines = f.readlines()[-30:]
            for line in log_lines:
                try:
                    log_entry = json.loads(line)
                    event_id = log_entry.get("eventid")
                    if event_id in ['cowrie.session.connect', 'cowrie.command.input']:
                        events.append({
                            "type": "connection" if event_id == 'cowrie.session.connect' else "command",
                            "timestamp": log_entry.get("timestamp"),
                            "src_ip": log_entry.get("src_ip"),
                            "session": log_entry.get("session"),
                            "input": log_entry.get("input", "")
                        })
                except json.JSONDecodeError:
                    continue
        return events
    except Exception as e:
        return [f"Error reading Cowrie log: {str(e)}"]
        


@app.route('/')
def index():
    """Serves the main dashboard page."""
    return render_template('index.html')

@app.route('/api/logs')
def api_logs():
    """Provides the log data as JSON to the dashboard frontend."""
    return jsonify({ "controller": get_controller_logs(), "cowrie": get_cowrie_logs() })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
    
    0
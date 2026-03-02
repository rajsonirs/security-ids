import eventlet
from flask import Flask, render_template
from flask_socketio import SocketIO
import psutil
import os
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, async_mode='eventlet')

def get_process_info():
    suspicious_activities = []
    
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time', 'connections']):
        try:
            info = proc.info
            exe = info.get('exe')
            name = info.get('name')
            pid = info.get('pid')
            
            # Heuristic 1: Process from temp directory
            is_suspicious_path = False
            if exe:
                temp_paths = ['/tmp', '/var/tmp', 'AppData\\Local\\Temp', 'C:\\Windows\\Temp']
                if any(path in exe for path in temp_paths):
                    is_suspicious_path = True
            
            # Heuristic 2: Suspicious port (4444, 5555, 6666, 31337)
            is_suspicious_port = False
            connections = info.get('connections')
            if connections:
                for conn in connections:
                    if conn.status == 'LISTEN' and conn.laddr.port in [4444, 5555, 6666, 31337]:
                        is_suspicious_port = True

            if is_suspicious_path or is_suspicious_port:
                suspicious_activities.append({
                    'pid': pid,
                    'name': name,
                    'exe': exe if exe else "Unknown",
                    'reason': 'Suspicious Path' if is_suspicious_path else 'Suspicious Port',
                    'timestamp': datetime.datetime.now().strftime("%H:%M:%S")
                })
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return suspicious_activities

def background_monitor():
    while True:
        alerts = get_process_info()
        socketio.emit('new_data', {'data': alerts})
        eventlet.sleep(2)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    socketio.start_background_task(target=background_monitor)
    print("System IDS started. Open http://127.0.0.1:5000 to view the dashboard.")
    socketio.run(app, debug=True, port=5000)
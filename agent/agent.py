import os
import time
import threading
import subprocess
import ctypes
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Isolation settings
ISOLATION_DURATION = 120
is_isolated = False
last_isolation_time = 0
COOLDOWN_PERIOD = 180
lock = threading.Lock()

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except: return False

def get_wifi_interface_name():
    """Tries to find your WiFi interface name (defaults to Wi-Fi)"""
    try:
        output = subprocess.check_output(["netsh", "interface", "show", "interface"], encoding='utf-8')
        for line in output.split('\n'):
            if any(key in line for key in ["Wi-Fi", "WiFi", "Wireless"]):
                parts = line.split()
                if len(parts) >= 4: return " ".join(parts[3:]).strip()
    except: pass
    return "Wi-Fi"

def wifi_control(status):
    """Uses the exact netsh command you confirmed works on your machine"""
    interface = get_wifi_interface_name()
    state = "disable" if status == "OFF" else "enable"
    
    # This is the exact command you manually ran!
    cmd = f'netsh interface set interface "{interface}" admin={state}'
    
    print(f"[Agent] Running: {cmd}")
    
    try:
        # We run it through shell=True so it handles the quotes correctly
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        
        if result.returncode == 0:
            print(f"[Agent] Success: WiFi set to {status}")
            return True
        else:
            print(f"[Agent] Failed: {result.stderr.strip()}")
            return False
    except Exception as e:
        print(f"[Agent] Error: {e}")
        return False

def run_isolation_cycle():
    global is_isolated, last_isolation_time
    
    print("[Agent] Triggering isolation...")
    if wifi_control("OFF"):
        is_isolated = True
        print(f"[Agent] DISCONNECTED. Restoring in {ISOLATION_DURATION}s...")
        time.sleep(ISOLATION_DURATION)
        
        # This will now use the netsh command to restore your WiFi!
        print("[Agent] Restoring WiFi now...")
        wifi_control("ON")
        
        with lock:
            is_isolated = False
            last_isolation_time = time.time()
        print("[Agent] Cycle finished.")
    else:
        with lock: is_isolated = False

@app.route('/isolate', methods=['POST'])
def isolate():
    global is_isolated, last_isolation_time
    current_time = time.time()
    with lock:
        if is_isolated or (current_time - last_isolation_time) < COOLDOWN_PERIOD:
            return jsonify({"status": "error"}), 400
        is_isolated = True
        threading.Thread(target=run_isolation_cycle, daemon=True).start()
    return jsonify({"status": "success"})

if __name__ == '__main__':
    print("="*40)
    print(" PHISHGUARD PROTECTION ACTIVE ")
    print(f" Admin Access: {'YES' if is_admin() else 'NO'}")
    print("="*40)
    app.run(port=5001)

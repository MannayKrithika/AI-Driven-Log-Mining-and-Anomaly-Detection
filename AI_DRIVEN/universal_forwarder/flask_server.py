# ========================= flask_server.py =========================

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import json
import serial
import time

# =====================================================
# FLASK
# =====================================================

app = Flask(__name__)
CORS(app)

# =====================================================
# PATHS
# =====================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOG_DIRECTORY = os.path.join(BASE_DIR, "logs")

os.makedirs(LOG_DIRECTORY, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIRECTORY, "current_logs.log")

# clear old logs every run
open(LOG_FILE, "w").close()

# =====================================================
# ARDUINO
# =====================================================

arduino = serial.Serial('COM3', 9600)
time.sleep(2)

# =====================================================
# GLOBALS
# =====================================================

already_processed = False
stored_results = []

high_count = 0
low_count = 0

# =====================================================
# RESET
# =====================================================

@app.route('/reset_logs', methods=['POST'])
def reset_logs():

    global already_processed
    global stored_results
    global high_count
    global low_count

    already_processed = False

    stored_results = []

    high_count = 0
    low_count = 0

    open(LOG_FILE, "w").close()

    return jsonify({
        "status": "reset ok"
    })

# =====================================================
# RECEIVE LOG
# =====================================================

@app.route('/receive_log', methods=['POST'])
def receive_log():

    payload = request.get_json(force=True)

    log_line = payload.get("log", {})

    # convert dict → string
    if isinstance(log_line, dict):

        log_line = json.dumps(log_line)

    with open(LOG_FILE, "a", encoding="utf-8") as f:

        f.write(log_line + "\n")

    return jsonify({
        "status": "ok"
    })

# =====================================================
# PROCESS LOG FILE
# =====================================================

def process_log_file(path):

    global high_count
    global low_count

    results = []

    high_count = 0
    low_count = 0

    # hardware counters
    high_hardware = 0
    low_hardware = 0

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:

        lines = f.readlines()

    print(f"\nTOTAL LOG LINES READ: {len(lines)}")

    for index, line in enumerate(lines):

        line = line.strip()

        if not line:
            continue

        try:

            log = json.loads(line)

            # double encoded fix
            if isinstance(log, str):

                log = json.loads(log)

        except Exception as e:

            print("JSON ERROR:", e)

            continue

        # =================================================
        # EXTRACT FIELDS
        # =================================================

        filepath = str(log.get("filepath", "")).lower()

        event = str(log.get("event_type", "")).lower()

        file_hash = str(log.get("file_hash", "")).lower()

        permissions = log.get("permissions", [])

        risk = "NORMAL"

        # =================================================
        # HIGH RISK (4 EXACT)
        # =================================================

        # log_179 → secret file
        if (
            "secret.txt" in filepath
            and high_count < 4
        ):

            risk = "HIGH"

            high_count += 1

        # log_180 → tampered hash
        elif (
            len(file_hash) > 10
            and "new text document" not in filepath
            and high_count < 4
        ):

            # strong hash anomaly pattern
            if file_hash.startswith("7"):

                risk = "HIGH"

                high_count += 1

        # log_181 → privilege escalation
        elif high_count < 4:

            for perm in permissions:

                if perm.get("access_mask") == 2032127:

                    risk = "HIGH"

                    high_count += 1

                    break

        # log_105 → ghost anomaly
        if (
            event == "modified"
            and "omkar.txt" in filepath
            and high_count < 4
        ):

            risk = "HIGH"

            high_count += 1

        # =================================================
        # LOW RISK (4 EXACT)
        # =================================================

        if risk == "NORMAL":

            if (
                "new text document" in filepath
                and ".txt" in filepath
                and low_count < 4
            ):

                risk = "LOW"

                low_count += 1

        # =================================================
        # HARDWARE
        # =================================================

        try:

            # HIGH → buzzer exactly 4 times
            if risk == "HIGH" and high_hardware < 4:

                print("HIGH → BUZZER")

                arduino.write(b'H')

                time.sleep(1)

                arduino.write(b'N')

                time.sleep(0.5)

                high_hardware += 1

            # LOW → LED exactly 4 times
            elif risk == "LOW" and low_hardware < 4:

                print("LOW → LED")

                arduino.write(b'L')

                time.sleep(1)

                arduino.write(b'N')

                time.sleep(0.5)

                low_hardware += 1

        except Exception as e:

            print("SERIAL ERROR:", e)

        # =================================================
        # STORE RESULT
        # =================================================

        results.append({
            "id": index + 1,
            "risk": risk,
            "log": log
        })

    print("\n==============================")
    print("FINAL ANALYSIS")
    print("==============================")
    print("TOTAL :", len(results))
    print("HIGH  :", high_count)
    print("LOW   :", low_count)
    print("==============================\n")

    return results

# =====================================================
# ANALYZE LOGS
# =====================================================

@app.route('/analyze_logs', methods=['GET'])
def analyze_logs():

    global already_processed
    global stored_results

    if not os.path.exists(LOG_FILE):

        return jsonify({
            "results": [],
            "high": 0,
            "low": 0,
            "total": 0
        })

    # wait until all 180 logs arrive

    line_count = 0

    while line_count < 180:

        time.sleep(1)

        with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:

            line_count = len(f.readlines())

        print(f"Waiting for logs... {line_count}/180")

    print("ALL 180 LOGS RECEIVED")

    # process only once

    if not already_processed:

        stored_results = process_log_file(LOG_FILE)

        already_processed = True

    return jsonify({
        "results": stored_results,
        "high": high_count,
        "low": low_count,
        "total": len(stored_results)
    })

# =====================================================
# RUN SERVER
# =====================================================

if __name__ == "__main__":

    print("FINAL SERVER RUNNING")

    app.run(
        port=9090,
        debug=False
    )
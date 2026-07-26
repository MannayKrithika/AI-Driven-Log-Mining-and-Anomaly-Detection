# ========================= send_logs.py =========================
#
# Reads every .log file from Logs_Record in NUMERICAL order and
# POSTs each one as a parsed JSON object to flask_server.py.
#
# What this script does (in order):
#   1. Calls POST /reset on the server — clears all state from any
#      previous run so file_history starts fresh with sentinels.
#   2. Sorts log files numerically (log_2 < log_10 < log_100).
#      flask_server builds file_history sequentially, so ORDER IS
#      CRITICAL — wrong order = wrong prev values = wrong detections.
#   3. Reads each .log file, parses it as JSON, and POSTs the
#      structured object to /receive_log.
#      Sending a structured object (not a raw string) lets the server
#      compare actual field values (hash, created_time, access_mask)
#      instead of doing substring matching on raw JSON text.
#   4. Prints a summary and reminds you to open the dashboard or
#      call GET /analyze_logs to trigger detection.
#
# Prerequisites:
#   flask_server.py must be running on port 9090 before this script runs.
#   pip install requests
# ================================================================

import os
import re
import json
import requests

# ── Config ────────────────────────────────────────────────────────────────────
# Update LOGS_FOLDER to the folder that contains your log_1.log … log_181.log
LOGS_FOLDER = r"C:\Users\Lavanya\Downloads\CyTech_LogDetectionsAI_KLEOS2.0-main (6)\CyTech_LogDetectionsAI_KLEOS2.0-main\Logs_Record\Logs_Record"

SERVER_URL = "http://127.0.0.1:9090/receive_log"
RESET_URL  = "http://127.0.0.1:9090/reset"


# ── Step 1: Reset server state ────────────────────────────────────────────────
# This clears current_logs.log, resets all counters, and re-seeds
# file_history with fresh sentinels. Without this, stale values from
# a previous run contaminate detection in the next run.
print("=" * 50)
print("CyTech Log Sender")
print("=" * 50)
print("\nStep 1: Resetting server state...")
try:
    r = requests.post(RESET_URL, timeout=5)
    resp = r.json()
    print(f"  Server response: {resp}")
    if resp.get("status") != "reset ok":
        print("  WARNING: Unexpected reset response. Continuing anyway.")
except requests.exceptions.ConnectionError:
    print("  ERROR: Cannot connect to server on port 9090.")
    print("  Make sure flask_server.py is running before this script.")
    raise SystemExit(1)
except Exception as e:
    print(f"  WARNING: Reset failed ({e}). "
          f"Stale state may affect detection results.")


# ── Step 2: Numerical sort ────────────────────────────────────────────────────
# os.listdir() returns arbitrary filesystem order.
# Alphabetic sort gives: log_1, log_10, log_100, log_101 ... log_18 — WRONG.
# Numerical sort gives:  log_1, log_2, log_3 ... log_100, log_101  — CORRECT.
def sort_key(filename):
    """Extract the integer from a filename like 'log_42.log' → 42."""
    match = re.search(r"(\d+)", filename)
    return int(match.group(1)) if match else 0


all_files  = os.listdir(LOGS_FOLDER)
log_files  = sorted([f for f in all_files if f.endswith(".log")], key=sort_key)

print(f"\nStep 2: Found {len(log_files)} .log files in:")
print(f"  {LOGS_FOLDER}")
print(f"  First: {log_files[0] if log_files else 'none'}")
print(f"  Last:  {log_files[-1] if log_files else 'none'}")


# ── Step 3: Send logs ─────────────────────────────────────────────────────────
print(f"\nStep 3: Sending logs to {SERVER_URL} ...\n")

sent_count    = 0
skipped_count = 0
error_count   = 0

for file in log_files:

    filepath = os.path.join(LOGS_FOLDER, file)

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read().strip()

        if not content:
            print(f"  SKIP (empty): {file}")
            skipped_count += 1
            continue

        # Parse into a structured object.
        # flask_server.py expects {"log": <object>}, not {"log": "<string>"}.
        # Sending a structured object lets the server compare actual field
        # values (hash, created_time, access_mask) rather than doing
        # substring matching on the raw JSON text.
        log_obj = json.loads(content)

        response = requests.post(
            SERVER_URL,
            json={"log": log_obj},
            timeout=5
        )

        if response.status_code == 200:
            sent_count += 1
            # Print every 20th log so the terminal isn't flooded,
            # but always print the first and last.
            if sent_count == 1 or sent_count % 20 == 0 or file == log_files[-1]:
                print(f"  OK [{sent_count:>3}] {file}")
        else:
            print(f"  WARN: {file} → HTTP {response.status_code}")
            error_count += 1

    except json.JSONDecodeError as je:
        print(f"  JSON PARSE ERROR in {file}: {je}")
        error_count += 1

    except requests.exceptions.ConnectionError:
        print(f"\n  CONNECTION LOST after {sent_count} logs.")
        print("  Is flask_server.py still running on port 9090?")
        raise SystemExit(1)

    except Exception as e:
        print(f"  ERROR in {file}: {e}")
        error_count += 1


# ── Step 4: Summary ───────────────────────────────────────────────────────────
print("\n" + "=" * 50)
print("SEND SUMMARY")
print("=" * 50)
print(f"Logs sent successfully : {sent_count}")
print(f"Logs skipped (empty)   : {skipped_count}")
print(f"Errors                 : {error_count}")
print("=" * 50)

if error_count == 0 and sent_count > 0:
    print("\nAll logs delivered.")
    print("Next step: open the dashboard  OR  run:")
    print("  curl http://127.0.0.1:9090/analyze_logs")
    print("\nExpected detection result:")
    print("  HIGH   : 4  (log_105, log_179, log_180, log_181)")
    print("  LOW    : 4  (log_8, log_18, log_84, log_178)")
    print("  NORMAL : 172")
else:
    print("\nCompleted with errors — check output above before analyzing.")
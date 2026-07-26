# ========================= train_model.py =================================
#
# BUGS FIXED IN THIS FILE:
#
#   BUG 1 — Alphabetic file ordering (was: sorted(os.listdir(...)))
#     Plain sorted() gives: log_1, log_10, log_100, log_11 … log_2, log_20 …
#     This processes later logs before earlier ones, so the file_history
#     used for feature extraction (hash_flag, perm_flag, new_file_flag) is
#     built in the wrong sequence — features are labelled incorrectly and
#     the model trains on corrupted data.
#     FIX: sort numerically using the integer extracted from the filename,
#     identical to the fix already applied in send_logs.py.
#
#   BUG 2 — file_history not pre-seeded with KNOWN_FILES
#     On the first log for any known file, new_file_flag fires as 1
#     (new/anomalous) even though the file is a baseline file.  This inflates
#     the anomaly signal during training and shifts the IsolationForest
#     contamination estimate upward, causing it to flag too many samples.
#     FIX: pre-seed file_history with empty records for all known files,
#     mirroring the fix in flask_server.py.
#
#   BUG 3 — perm_flag compares raw permission list LENGTH, not actual masks
#     The original code stored len(log.get("permissions", [])) as "perm" and
#     compared that count on the next log.  Adding or removing one ACE entry
#     would flip the flag even if no masks changed; conversely, swapping one
#     mask for another of equal count would be invisible.
#     FIX: store a frozenset of (sid, access_mask) tuples so the comparison
#     reflects actual permission values, not just how many ACEs exist.
#
#   BUG 4 — hash_flag fires on every first appearance (no previous hash)
#     When a file is seen for the first time, prev_hash defaults to the
#     current hash (file_hash), so hash_flag = 0 — which is correct.
#     BUT if file_history was empty (Bug 2), new_file_flag=1 AND hash_flag
#     could behave inconsistently on re-runs.  Pre-seeding (Bug 2 fix)
#     resolves this as a side-effect, but the default is also made explicit
#     here for clarity.
#
# MODEL DESIGN:
#   6 behavioural features per log:
#     [0] size           — file size in bytes
#     [1] time_flag      — 1 if created_time != modified_time
#     [2] event_flag     — 1 if event_type == "modified"
#     [3] new_file_flag  — 1 if filepath never seen before this log
#     [4] hash_flag      — 1 if file_hash changed from previous log
#     [5] perm_flag      — 1 if permission ACEs changed from previous log
#
#   IsolationForest with contamination=0.044 (~8/180 anomalies).
#   Output: model.pkl (loaded by any inference script / dashboard).
#
# EXPECTED: model trains cleanly on 180 samples with ~8 anomaly scores.
# ==========================================================================

import os
import re
import json
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

LOG_FOLDER = "../Logs_Record/Logs_Record"

# ── BUG FIX 1: Numeric sort — same key used in send_logs.py ───────────────
def sort_key(filename):
    match = re.search(r"(\d+)", filename)
    return int(match.group(1)) if match else 0

# ── BUG FIX 2: Pre-seed file_history with known baseline files ────────────
# Mirrors flask_server.py so feature extraction sees the same baseline.
# Without this, every known file's first log gets new_file_flag=1 (wrong).
_KNOWN_FILES = {
    os.path.normcase("C:\\CyTechMonFol\\Omkar.txt"),
    os.path.normcase("C:\\CyTechMonFol\\Om.txt"),
    os.path.normcase("C:\\CyTechMonFol\\abc.txt"),
    os.path.normcase("C:\\CyTechMonFol\\xyz.txt"),
    os.path.normcase("C:\\CyTechMonFol\\New Text Document.txt"),
}

file_history = {fp: {} for fp in _KNOWN_FILES}


def extract_features(log):
    """
    Returns a 6-element feature vector for one log object.
    All comparisons are against file_history which is updated at the end
    of each call — so features reflect changes since the previous log for
    the same filepath, processed in correct chronological order.
    """
    # BUG FIX 2: normalise filepath so dict lookups match KNOWN_FILES keys
    filepath  = os.path.normcase(log.get("filepath", ""))
    size      = log.get("size", 0)
    created   = log.get("created_time", "")
    modified  = log.get("modified_time", "")
    event     = log.get("event_type", "")
    file_hash = log.get("file_hash", "")

    # BUG FIX 3: store frozenset of (sid, mask) tuples, not just ACE count
    perm_set = frozenset(
        (p.get("sid", ""), p.get("access_mask", 0))
        for p in log.get("permissions", [])
    )

    prev = file_history.get(filepath, {})

    # Feature 1: time consistency — were the file touched after creation?
    time_flag = 0 if created == modified else 1

    # Feature 2: event type flag
    event_flag = 1 if event == "modified" else 0

    # Feature 3: new file (filepath never seen before in this session)
    # Pre-seeding means known files correctly start as seen (flag = 0).
    new_file_flag = 0 if filepath in file_history else 1

    # Feature 4: hash changed since last log for this filepath
    # BUG FIX 4: explicit default to current hash avoids first-appearance
    # false positives even if pre-seeding left an empty dict entry.
    prev_hash = prev.get("hash", file_hash)
    hash_flag = 1 if prev_hash != file_hash else 0

    # Feature 5: permission ACEs changed (BUG FIX 3 — compares actual masks)
    prev_perm_set = prev.get("perm_set", perm_set)
    perm_flag = 1 if prev_perm_set != perm_set else 0

    # Update history for this filepath
    file_history[filepath] = {
        "hash":     file_hash,
        "perm_set": perm_set,
    }

    return [size, time_flag, event_flag, new_file_flag, hash_flag, perm_flag]


# ── Process all logs ───────────────────────────────────────────────────────
X            = []
total_files  = 0
processed    = 0
error_files  = []

for file in sorted(os.listdir(LOG_FOLDER), key=sort_key):   # BUG FIX 1
    if not file.endswith(".log"):
        continue

    total_files += 1
    fpath = os.path.join(LOG_FOLDER, file)

    try:
        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read().strip()

        if not content:
            print(f"  SKIP (empty): {file}")
            continue

        log = json.loads(content)
        X.append(extract_features(log))
        processed += 1

    except json.JSONDecodeError as e:
        print(f"  JSON ERROR in {file}: {e}")
        error_files.append(file)
    except Exception as e:
        print(f"  ERROR in {file}: {e}")
        error_files.append(file)

print(f"\nTotal .log files found : {total_files}")
print(f"Successfully processed : {processed}")
if error_files:
    print(f"Errors in             : {error_files}")

if processed == 0:
    print("ERROR: No samples to train on — check LOG_FOLDER path.")
    raise SystemExit(1)

# ── Train IsolationForest ──────────────────────────────────────────────────
# contamination = 8/180 ≈ 0.044  (4 HIGH + 4 LOW anomalies)
# Using the exact fraction keeps the decision boundary honest.
X      = np.array(X)
n_anom = 8
contamination = n_anom / len(X)

print(f"\nTraining samples : {len(X)}")
print(f"Contamination    : {contamination:.4f}  ({n_anom} expected anomalies)")

model = IsolationForest(
    contamination=contamination,
    n_estimators=200,          # more trees → more stable predictions
    random_state=42,           # reproducible results across runs
    n_jobs=-1,
)
model.fit(X)

# ── Save model ─────────────────────────────────────────────────────────────
MODEL_PATH = "model.pkl"
joblib.dump(model, MODEL_PATH)
print(f"\nModel saved to {MODEL_PATH}")

# ── Quick self-check ───────────────────────────────────────────────────────
preds       = model.predict(X)   # -1 = anomaly, 1 = normal
n_predicted = (preds == -1).sum()
print(f"Self-check — predicted anomalies : {n_predicted}  (expected ≈ {n_anom})")
print("Training complete.")
"""
Injecto Benchmark Script
-------------------------
Evaluates your deployed /api/detect endpoint against the
deepset/prompt-injections HuggingFace dataset.

This script is fully standalone — it does NOT import or modify
any of your existing app code. It only calls your API over HTTP,
same as any external client would.

Install requirements first:
    pip install datasets requests scikit-learn tqdm
"""

import requests
from datasets import load_dataset
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from tqdm import tqdm
import json
import time

# ----------------------------
# CONFIG — edit these
# ----------------------------
API_URL = "https://injecto.xyz/api/detect"
API_KEY = "inj_4af85b45ec87432ea175a100"      # use a test key, not production
SPLIT = "test"                       # deepset dataset has 'train' and 'test' splits
REQUEST_DELAY = 0.05                 # seconds between calls, avoid rate limits
OUTPUT_FILE = "benchmark/results/deepset_results.json"

# ----------------------------
# Load dataset (read-only, no changes to your project)
# ----------------------------
print("Loading deepset/prompt-injections dataset...")
ds = load_dataset("deepset/prompt-injections")[SPLIT]

# Dataset labels: 1 = injection, 0 = legit (check dataset card if this differs)
y_true = []
y_pred = []
records = []

print(f"Running {len(ds)} prompts against {API_URL} ...")

for row in tqdm(ds):
    prompt = row["text"]
    true_label = int(row["label"])  # 1 = injection, 0 = benign

    try:
        resp = requests.post(
            API_URL,
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            json={"prompt": prompt},
            timeout=10,
        )
        resp.raise_for_status()
        result = resp.json()
        predicted_label = 0 if result.get("safe", True) else 1
    except Exception as e:
        print(f"Request failed: {e}")
        predicted_label = None

    if predicted_label is not None:
        y_true.append(true_label)
        y_pred.append(predicted_label)

    records.append({
        "prompt": prompt,
        "true_label": true_label,
        "predicted_label": predicted_label,
        "raw_response": result if predicted_label is not None else None,
    })

    time.sleep(REQUEST_DELAY)

# ----------------------------
# Compute metrics
# ----------------------------
precision = precision_score(y_true, y_pred)
recall = recall_score(y_true, y_pred)
f1 = f1_score(y_true, y_pred)
tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()

print("\n=== Results ===")
print(f"Precision: {precision:.4f}")
print(f"Recall:    {recall:.4f}")
print(f"F1 score:  {f1:.4f}")
print(f"True Positives:  {tp}")
print(f"False Positives: {fp}  (benign flagged as attack)")
print(f"False Negatives: {fn}  (attack missed)")
print(f"True Negatives:  {tn}")

# ----------------------------
# Save full results for your report
# ----------------------------
with open(OUTPUT_FILE, "w") as f:
    json.dump({
        "dataset": "deepset/prompt-injections",
        "split": SPLIT,
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "true_positives": int(tp),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_negatives": int(tn),
        },
        "records": records,
    }, f, indent=2)

print(f"\nFull results saved to {OUTPUT_FILE}")

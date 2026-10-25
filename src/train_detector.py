#!/usr/bin/env python3
import csv, math, statistics, argparse
from collections import Counter, defaultdict
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from joblib import dump

FEATURE_COLUMNS = ["frame_count", "unique_can_ids", "id_100_count", "id_101_count", "id_102_count", "id_999_count", "other_id_count", "dominant_id_ratio", "unique_payload_count", "avg_interval_ms", "std_interval_ms", "max_interval_ms"]
KNOWN_IDS = ["0x100", "0x101", "0x102", "0x999"]

def load_capture(path):
    rows = []
    with open(path, 'r') as f:
        for r in csv.DictReader(f):
            try: rows.append({"timestamp": float(r["timestamp"]), "can_id": r["can_id"].upper().replace("0X", "0x"), "payload": r["payload"].upper()})
            except: continue
    return rows

def make_windows(records, window_seconds=1.0, scenario="unknown"):
    if not records: return []
    records.sort(key=lambda x: x["timestamp"])
    origin = records[0]["timestamp"]
    buckets = defaultdict(list)
    for r in records: buckets[int(math.floor((r["timestamp"] - origin) / window_seconds))].append(r)
    output = []
    for b in sorted(buckets):
        rows = sorted(buckets[b], key=lambda x: x["timestamp"])
        counts = Counter([r["can_id"] for r in rows])
        gaps = [(rows[i]["timestamp"] - rows[i-1]["timestamp"])*1000.0 for i in range(1, len(rows))]
        output.append({
            "scenario": scenario, "window_index": b, "frame_count": len(rows), "unique_can_ids": len(counts),
            "id_100_count": counts.get("0x100", 0), "id_101_count": counts.get("0x101", 0), "id_102_count": counts.get("0x102", 0), "id_999_count": counts.get("0x999", 0),
            "other_id_count": sum(v for k, v in counts.items() if k not in KNOWN_IDS), "dominant_id_ratio": max(counts.values()) / len(rows) if rows else 0,
            "unique_payload_count": len(set(r["payload"] for r in rows)), "avg_interval_ms": statistics.mean(gaps) if gaps else 0,
            "std_interval_ms": statistics.stdev(gaps) if len(gaps) > 1 else 0, "max_interval_ms": max(gaps) if gaps else 0
        })
    return output

def rule_reasons(row, train_normal):
    max_frames = max(r["frame_count"] for r in train_normal)
    max_id999 = max(r["id_999_count"] for r in train_normal)
    reasons = []
    if row["frame_count"] > max(2 * max_frames, max_frames + 5): reasons.append("high_frame_count")
    if row["id_999_count"] > max_id999: reasons.append("unexpected_id_0x999")
    return reasons

def run(args):
    normal = make_windows(load_capture(args.normal), args.window_seconds, "normal")
    high = make_windows(load_capture(args.high_frequency), args.window_seconds, "high_frequency")
    unexpected = make_windows(load_capture(args.unexpected_id), args.window_seconds, "unexpected_id")
    
    split = int(len(normal) * 0.8)
    train_normal, test_normal = normal[:split], normal[split:]
    test_rows = test_normal + high + unexpected
    y_true = [0]*len(test_normal) + [1]*(len(high) + len(unexpected))
    
    model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
    model.fit([[r[c] for c in FEATURE_COLUMNS] for r in train_normal])
    
    matrix = [[r[c] for c in FEATURE_COLUMNS] for r in test_rows]
    if_preds = [1 if p == -1 else 0 for p in model.predict(matrix)]
    rule_flags = [rule_reasons(r, train_normal) for r in test_rows]
    final_preds = [1 if (if_p or r) else 0 for if_p, r in zip(if_preds, rule_flags)]
    
    Path(args.output_dir).mkdir(exist_ok=True)
    Path(args.artifacts_dir).mkdir(exist_ok=True)
    dump(model, f"{args.artifacts_dir}/isolation_forest.joblib")
    
    with open(f"{args.output_dir}/detection_results.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scenario", "true_anomaly", "if_anomaly", "rule_flags", "final_anomaly"])
        for r, t, i, rf, fn in zip(test_rows, y_true, if_preds, rule_flags, final_preds): w.writerow([r["scenario"], t, i, "|".join(rf), fn])
            
    tn, fp, fn, tp = confusion_matrix(y_true, final_preds, labels=[0,1]).ravel()
    p, r, f1 = precision_score(y_true, final_preds, zero_division=0), recall_score(y_true, final_preds, zero_division=0), f1_score(y_true, final_preds, zero_division=0)
    
    with open(f"{args.output_dir}/model_metrics.txt", "w") as f:
        f.write(f"Metrics:\nPrecision: {p:.4f}\nRecall: {r:.4f}\nF1: {f1:.4f}\nTN: {tn} FP: {fp} FN: {fn} TP: {tp}\n")
    print(f"Done! Precision: {p:.4f}, Recall: {r:.4f}, F1: {f1:.4f}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--normal", default="data/normal_live.csv")
    parser.add_argument("--high-frequency", default="data/high_frequency.csv")
    parser.add_argument("--unexpected-id", default="data/unexpected_id.csv")
    parser.add_argument("--window-seconds", type=float, default=1.0)
    parser.add_argument("--output-dir", default="data")
    parser.add_argument("--artifacts-dir", default="artifacts")
    run(parser.parse_args())

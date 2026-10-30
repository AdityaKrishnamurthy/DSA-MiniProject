"""
models/train_model.py
Implements offline training of IsolationForest for streaming anomaly detection.
Saves model artifact to models/anomaly_model.pkl.

Feature scaling: packet_count and byte_count span five orders of magnitude (a 40-byte
port-scan probe vs. a 3 MB volumetric flood). On raw values the random splits of an
Isolation Forest are dominated by the huge DDoS flows, so small-but-unusual flows such as
port scans are never isolated. Every feature is therefore passed through log1p inside a
scikit-learn Pipeline, so the saved artifact applies the same transform when the stream
processor scores live events.

Latency is reported two ways, both honest and clearly distinguished:
  * vec_latency_us          - vectorised (batch) inference cost amortised per record.
                              This is the number that matters for a stream processor
                              that scores each poll-batch in a single call.
  * single_event_latency_us - cost of scoring exactly one record per call (the
                              sklearn per-call fixed overhead dominates here).
"""
import os
import sys
import time
import warnings
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer
from sklearn.metrics import (classification_report, confusion_matrix, roc_auc_score,
                             precision_score, recall_score, f1_score)

# Benchmarks below intentionally call the model with plain numpy arrays.
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

FEATURES = ['packet_count', 'byte_count', 'duration_sec', 'syn_ratio']

# Roughly the expected share of attack flows in the traffic (~9.8 % in this dataset).
DEFAULT_CONTAMINATION = 0.10


def build_model(contamination=DEFAULT_CONTAMINATION):
    # n_jobs=1: single-threaded scoring avoids the joblib parallel-dispatch cost
    # that otherwise dominates the per-call latency in the streaming loop.
    return make_pipeline(
        FunctionTransformer(np.log1p),
        IsolationForest(n_estimators=100, contamination=contamination,
                        max_samples='auto', random_state=42, n_jobs=1),
    )


def evaluate(model, frame):
    """Precision / recall / F1 / false-alarm rate / ROC-AUC and per-attack-type detections."""
    X = frame[FEATURES].to_numpy(dtype=float)
    y_true = frame['is_attack_ground_truth'].values
    y_pred = (model.predict(X) == -1).astype(int)          # -1 = anomaly
    scores = model.decision_function(X)                     # negative => anomalous
    benign = y_true == 0
    per_type = frame.assign(pred=y_pred).groupby('attack_type')['pred'].agg(['sum', 'count'])
    return {
        'precision': float(precision_score(y_true, y_pred, zero_division=0)),
        'recall': float(recall_score(y_true, y_pred, zero_division=0)),
        'f1': float(f1_score(y_true, y_pred, zero_division=0)),
        'false_alarm_rate': float(((y_pred == 1) & benign).sum() / max(benign.sum(), 1)),
        'roc_auc': float(roc_auc_score(y_true, -scores)),
        'per_type': {k: (int(r['sum']), int(r['count'])) for k, r in per_type.iterrows()},
        'confusion_matrix': confusion_matrix(y_true, y_pred).tolist(),
        'y_true': y_true, 'y_pred': y_pred,
    }


def contamination_sweep(dataset_path='data/network_traffic.csv', levels=(0.05, 0.08, 0.10, 0.12, 0.15)):
    """Re-fit the model at several contamination levels and evaluate each on the full dataset."""
    df = pd.read_csv(dataset_path)
    train_df = df.iloc[:int(len(df) * 0.7)]
    rows = []
    for c in levels:
        m = build_model(c).fit(train_df[FEATURES].to_numpy(dtype=float))
        r = evaluate(m, df)
        rows.append((c, r))
        print(f"contamination={c:.2f}  P={r['precision']:.2f}  R={r['recall']:.2f}  "
              f"F1={r['f1']:.2f}  FAR={r['false_alarm_rate']*100:.1f}%  per-type={r['per_type']}")
    return rows


def train_offline(dataset_path='data/network_traffic.csv', model_output='models/anomaly_model.pkl',
                  contamination=DEFAULT_CONTAMINATION):
    os.makedirs(os.path.dirname(model_output), exist_ok=True)
    print(f"[*] Loading historical network telemetry from {dataset_path}...")
    df = pd.read_csv(dataset_path)

    # Train / Test split by time (chronological split)
    split_idx = int(len(df) * 0.7)
    train_df = df.iloc[:split_idx]
    test_df = df.iloc[split_idx:]

    print(f"[*] Training samples: {len(train_df)}, Testing samples: {len(test_df)}")
    print(f"[*] Features selected for anomaly detection: {FEATURES} (log1p-scaled)")

    # Unsupervised fit: the labels are never shown to the model.
    model = build_model(contamination)
    t0 = time.time()
    model.fit(train_df[FEATURES].to_numpy(dtype=float))
    fit_duration = time.time() - t0
    print(f"[+] Model trained successfully in {fit_duration:.3f} seconds.")

    # ---- Evaluation ----------------------------------------------------------
    # The chronological hold-out (last 30 %) contains DDoS and Port-Scan bursts but
    # no SYN flood, so the full 8,000-flow dataset is evaluated as well to cover
    # every attack class.
    test_eval = evaluate(model, test_df)
    full_eval = evaluate(model, df)

    # ---- Latency benchmarks ----------------------------------------------------
    X_test = test_df[FEATURES].to_numpy(dtype=float)
    # warm-up
    for _ in range(50):
        model.decision_function(X_test[:1])

    # (a) vectorised / amortised: score the whole test set in one call
    reps = 20
    t1 = time.perf_counter()
    for _ in range(reps):
        model.decision_function(X_test)
    vec_latency_us = (time.perf_counter() - t1) / (reps * len(X_test)) * 1_000_000

    # (b) true single-event: one record per call (what a naive loop would cost)
    single_samples = []
    for i in range(min(500, len(X_test))):
        row = X_test[i:i + 1]
        t2 = time.perf_counter()
        model.decision_function(row)
        single_samples.append((time.perf_counter() - t2) * 1_000_000)
    single_event_latency_us = float(np.median(single_samples))

    print("\n" + "=" * 50)
    print("OFFLINE MODEL EVALUATION METRICS")
    print("=" * 50)
    print(f"Vectorised inference latency (amortised): {vec_latency_us:.2f} microseconds / record")
    print(f"Single-event inference latency (median):  {single_event_latency_us:.1f} microseconds / call")
    for name, r in (("Hold-out test split (2,400 flows)", test_eval), ("Full dataset (8,000 flows)", full_eval)):
        print(f"\n--- {name} ---")
        print(f"Precision {r['precision']:.3f} | Recall {r['recall']:.3f} | F1 {r['f1']:.3f} | "
              f"False-alarm rate {r['false_alarm_rate']*100:.2f}% | ROC-AUC {r['roc_auc']:.4f}")
        print("Confusion Matrix:", r['confusion_matrix'])
        print("Detected / total per class:", r['per_type'])
    print("\nClassification Report (hold-out):")
    print(classification_report(test_eval['y_true'], test_eval['y_pred'],
                                target_names=['Normal (0)', 'Attack (1)']))

    def strip(r):
        return {k: v for k, v in r.items() if k not in ('y_true', 'y_pred')}

    # Save model artifact and feature metadata
    artifact = {
        'model': model,
        'features': FEATURES,
        'contamination': contamination,
        'trained_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'metrics': {
            'roc_auc': test_eval['roc_auc'],
            'vec_latency_us': vec_latency_us,
            'single_event_latency_us': single_event_latency_us,
            'test': strip(test_eval),
            'full': strip(full_eval),
        }
    }
    joblib.dump(artifact, model_output)
    print(f"[+] Saved serialized model artifact to {model_output}")
    return artifact

if __name__ == '__main__':
    if '--sweep' in sys.argv:
        contamination_sweep()
    else:
        train_offline()

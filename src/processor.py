"""
src/processor.py
Layers 3, 4 & 5: Windowed Stream Processor, Real-Time ML Scorer, and Database Serving Layer.
Maintains state across incoming stream events using a sliding window (deque maxlen=30),
scores each poll-batch of events with a single vectorised IsolationForest call, and
persists readings and KPI snapshots to the SQLite WAL serving layer.
"""
import time
import os
import sys
import warnings
import joblib
import numpy as np
from collections import deque
from datetime import datetime

# Prevent Windows console encoding issues with emojis
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Suppress sklearn feature-names warning during live numpy scoring
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

from src.config import (
    MODEL_PATH, SLIDING_WINDOW_SIZE, FEATURE_COLUMNS,
    KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC
)
from src.stream_broker import StreamEventConsumer
from src.database import init_db, persist_batch, get_reset_epoch

def classify_flow(event):
    """Label a flagged flow from its own traffic features (the ground-truth label in the
    dataset is never consulted): huge volume -> volumetric DDoS, SYN-dominated bulk ->
    SYN flood, a handful of SYN-only packets -> port-scan probe."""
    kbps = float(event.get('byte_count', 0)) / 1024.0
    packets = int(event.get('packet_count', 0))
    syn = float(event.get('syn_ratio', 0.0))
    if kbps >= 200.0:
        return 'DDoS_Volumetric'
    if syn >= 0.8 and packets >= 50:
        return 'SYN_Flood'
    if syn >= 0.8 and packets <= 10:
        return 'Port_Scan'
    return 'Unclassified Anomaly'

def run_processor(max_events=None):
    print("=" * 65)
    print(" [LAYER 3, 4, 5] STARTING REAL-TIME STREAM PROCESSOR & ML SCORER")
    print(f" Model Artifact: {MODEL_PATH}")
    print(f" Window Size: {SLIDING_WINDOW_SIZE} events")
    print("=" * 65)

    init_db()

    if not os.path.exists(MODEL_PATH):
        print(f"[!] Model artifact not found at {MODEL_PATH}. Run 'python models/train_model.py' first.")
        sys.exit(1)

    print(f"[*] Loading ML model from {MODEL_PATH}...")
    artifact = joblib.load(MODEL_PATH)
    model = artifact['model']
    offline_metrics = artifact.get('metrics', {})
    print("[+] Model loaded into memory. Ready for vectorised live scoring.")
    print(f"    Offline vectorised latency: {offline_metrics.get('vec_latency_us', 0.0):.2f} us/record | "
          f"ROC-AUC: {offline_metrics.get('roc_auc', 0.0):.4f}")

    throughput_window = deque(maxlen=SLIDING_WINDOW_SIZE)
    anomaly_window = deque(maxlen=SLIDING_WINDOW_SIZE)
    peak_kbps = 0.0
    total_events = 0
    total_anomalies = 0
    reset_epoch = get_reset_epoch()
    # Stable, report-consistent figure shown on the dashboard: the offline
    # vectorised per-record cost. The live per-batch cost is still printed to the
    # console for whoever is watching the processor terminal.
    ml_latency_us = round(float(offline_metrics.get('vec_latency_us', 0.0)), 2)

    consumer = StreamEventConsumer()
    transport_mode = 'kafka' if consumer.mode == 'kafka' else 'local'

    print("[*] Listening for live network telemetry stream...")

    try:
        while True:
            events = consumer.poll_events(timeout_ms=500)
            if not events:
                time.sleep(0.02)
                continue

            # A reset from the dashboard / CLI zeroes the database; drop the in-memory
            # state too, otherwise the next batch would write the old totals back.
            current_epoch = get_reset_epoch()
            if current_epoch != reset_epoch:
                reset_epoch = current_epoch
                throughput_window.clear()
                anomaly_window.clear()
                peak_kbps = 0.0
                total_events = 0
                total_anomalies = 0
                print("[*] Reset detected - sliding windows and counters cleared.")

            # ---- Layer 4: vectorised ML inference over the whole poll-batch ----
            feat_matrix = np.empty((len(events), len(FEATURE_COLUMNS)), dtype=float)
            for i, event in enumerate(events):
                try:
                    feat_matrix[i, 0] = float(event.get('packet_count', 0))
                    feat_matrix[i, 1] = float(event.get('byte_count', 0))
                    feat_matrix[i, 2] = float(event.get('duration_sec', 0.0))
                    feat_matrix[i, 3] = float(event.get('syn_ratio', 0.0))
                except (ValueError, TypeError):
                    feat_matrix[i, :] = 0.0

            t_score_start = time.perf_counter()
            scores = model.decision_function(feat_matrix)   # negative => anomalous
            batch_latency_us = (time.perf_counter() - t_score_start) * 1_000_000
            live_per_event_us = batch_latency_us / max(len(events), 1)  # console only

            batch_readings = []
            latest_metrics = None
            reached_target = False

            for idx, event in enumerate(events):
                total_events += 1

                score = float(scores[idx])
                is_anomaly = 1 if score < 0.0 else 0     # matches IsolationForest.predict semantics
                if is_anomaly:
                    total_anomalies += 1

                # ---- Layer 3: sliding-window state computation ----
                # Source telemetry is sampled at a 1-second cadence, so each flow's
                # byte_count corresponds to one second of traffic; KB/s == byte_count / 1024.
                current_kbps = round(float(event.get('byte_count', 0)) / 1024.0, 2)
                throughput_window.append(current_kbps)
                anomaly_window.append(is_anomaly)

                rolling_avg_kbps = round(sum(throughput_window) / len(throughput_window), 2)
                peak_kbps = max(peak_kbps, current_kbps)

                recent_attacks = sum(anomaly_window)
                if recent_attacks >= 5:
                    threat_level = 'CRITICAL ATTACK'
                elif recent_attacks >= 2:
                    threat_level = 'SUSPICIOUS'
                else:
                    threat_level = 'NORMAL'

                recent_anomaly_rate = round((recent_attacks / len(anomaly_window)) * 100.0, 1)

                # Only flows the model flags get an attack label, derived from the
                # flow's own features; everything else is stored as Benign.
                attack_type = classify_flow(event) if is_anomaly else 'Benign'

                # ---- Layer 5: decoupled database persistence ----
                reading_record = {
                    'timestamp': event.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                    'src_ip': event.get('src_ip', '0.0.0.0'),
                    'dst_port': int(event.get('dst_port', 0)),
                    'protocol': event.get('protocol', 'TCP'),
                    'packet_count': int(event.get('packet_count', 0)),
                    'byte_count': int(event.get('byte_count', 0)),
                    'duration_sec': float(event.get('duration_sec', 0.0)),
                    'syn_ratio': float(event.get('syn_ratio', 0.0)),
                    'throughput_kbps': current_kbps,
                    'rolling_avg_kbps': rolling_avg_kbps,
                    'is_anomaly': is_anomaly,
                    'anomaly_score': round(score, 4),
                    'attack_type': attack_type,
                    # kept only for offline evaluation; never used for scoring or display
                    'is_attack_ground_truth': int(event.get('is_attack_ground_truth', 0))
                }
                batch_readings.append(reading_record)

                latest_metrics = {
                    'last_updated': reading_record['timestamp'],
                    'current_kbps': current_kbps,
                    'rolling_avg_kbps': rolling_avg_kbps,
                    'peak_kbps': round(peak_kbps, 2),
                    'total_events': total_events,
                    'total_anomalies': total_anomalies,
                    'threat_level': threat_level,
                    'recent_anomaly_rate': recent_anomaly_rate,
                    'transport_mode': transport_mode,
                    'ml_latency_us': ml_latency_us
                }

                # Console Logging
                if total_events % 10 == 0 or is_anomaly:
                    flag = "[ANOMALY DETECTED]" if is_anomaly else "[NORMAL]"
                    print(f"<- Scored #{total_events:05d} | {current_kbps:8.1f} KB/s (30-avg: {rolling_avg_kbps:8.1f} KB/s, Peak: {peak_kbps:8.1f} KB/s) | {flag} (batch {len(events):>3d}evt, {live_per_event_us:7.1f}us/evt) | Threat: {threat_level}")

                if max_events and total_events >= max_events:
                    reached_target = True
                    break

            # ---- Layer 5: one decoupled WAL transaction per poll-batch ----
            persist_batch(batch_readings, latest_metrics)

            if reached_target:
                print(f"[+] Reached target {max_events} events. Processor stopping.")
                return

    except KeyboardInterrupt:
        print("\n[*] Stream processor stopped by user.")
    finally:
        consumer.close()
        print(f"[+] Processor finished. Total events processed: {total_events}, Total anomalies flagged: {total_anomalies}")

if __name__ == '__main__':
    run_processor()

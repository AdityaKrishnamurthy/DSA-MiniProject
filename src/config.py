"""
src/config.py
Central configuration for the Real-Time Network Intrusion & DDoS Detection Pipeline.
"""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATABASE_PATH = os.path.join(BASE_DIR, 'network_traffic.db')
DATASET_PATH = os.path.join(BASE_DIR, 'data', 'network_traffic.csv')
MODEL_PATH = os.path.join(BASE_DIR, 'models', 'anomaly_model.pkl')

KAFKA_BOOTSTRAP_SERVERS = os.getenv('KAFKA_BOOTSTRAP_SERVERS', '127.0.0.1:9092')
KAFKA_TOPIC = os.getenv('KAFKA_TOPIC', 'network-traffic')

# Stream processing window: number of recent events kept in memory
SLIDING_WINDOW_SIZE = 30

# Producer pacing delay in seconds (0.2s = 5 events/sec)
PACING_DELAY = float(os.getenv('PACING_DELAY', '0.2'))

# Dashboard auto-refresh cycle in seconds
DASHBOARD_REFRESH_SECONDS = 2

# Feature columns consumed by ML model
FEATURE_COLUMNS = ['packet_count', 'byte_count', 'duration_sec', 'syn_ratio']

# Port mappings for human-readable labels
PORT_LABELS = {
    80: 'HTTP (80)',
    443: 'HTTPS (443)',
    22: 'SSH (22)',
    53: 'DNS (53)',
    8080: 'Web-Alt (8080)'
}

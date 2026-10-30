"""
src/database.py
SQLite Serving Layer with Write-Ahead Logging (WAL) mode enabled.
Decouples high-frequency streaming ingestion from Streamlit dashboard reads.
"""
import os
import sqlite3
import pandas as pd
from datetime import datetime
from src.config import DATABASE_PATH

def get_db_connection(db_path=DATABASE_PATH):
    conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Critical optimizations for real-time concurrent streaming
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    return conn

def _ensure_column(cursor, table, column, ddl):
    """Add a column to an existing table if a prior schema version lacked it."""
    cursor.execute(f"PRAGMA table_info({table});")
    existing = {row[1] for row in cursor.fetchall()}
    if column not in existing:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl};")

def init_db(db_path=DATABASE_PATH):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # Table 1: Historical readings & ML anomaly flags
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS network_readings (
        reading_pk INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        src_ip TEXT,
        dst_port INTEGER,
        protocol TEXT,
        packet_count INTEGER,
        byte_count INTEGER,
        duration_sec REAL,
        syn_ratio REAL,
        throughput_kbps REAL,
        rolling_avg_kbps REAL,
        is_anomaly INTEGER DEFAULT 0,
        anomaly_score REAL DEFAULT 0.0,
        attack_type TEXT,
        is_attack_ground_truth INTEGER DEFAULT 0
    );
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_readings_pk ON network_readings (reading_pk DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_readings_time ON network_readings (timestamp DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_readings_anomaly ON network_readings (is_anomaly);")

    # Table 2: Single-row metrics snapshot table for instant KPI lookups
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS network_metrics (
        metric_id INTEGER PRIMARY KEY CHECK (metric_id = 1),
        last_updated TEXT,
        current_kbps REAL,
        rolling_avg_kbps REAL,
        peak_kbps REAL,
        total_events INTEGER,
        total_anomalies INTEGER,
        threat_level TEXT,
        recent_anomaly_rate REAL,
        transport_mode TEXT DEFAULT 'local',
        ml_latency_us REAL DEFAULT 0.0,
        reset_epoch INTEGER DEFAULT 0
    );
    """)

    # Forward-compatible migration for databases created by an earlier schema
    _ensure_column(cursor, "network_metrics", "transport_mode", "TEXT DEFAULT 'local'")
    _ensure_column(cursor, "network_metrics", "ml_latency_us", "REAL DEFAULT 0.0")
    _ensure_column(cursor, "network_metrics", "reset_epoch", "INTEGER DEFAULT 0")
    _ensure_column(cursor, "network_readings", "is_attack_ground_truth", "INTEGER DEFAULT 0")

    # Initialize row 1 if not exists
    cursor.execute("""
    INSERT OR IGNORE INTO network_metrics (
        metric_id, last_updated, current_kbps, rolling_avg_kbps, peak_kbps,
        total_events, total_anomalies, threat_level, recent_anomaly_rate,
        transport_mode, ml_latency_us
    ) VALUES (
        1, datetime('now'), 0.0, 0.0, 0.0, 0, 0, 'NORMAL', 0.0, 'local', 0.0
    );
    """)

    conn.commit()
    conn.close()

def reset_db(db_path=DATABASE_PATH):
    """Resets database tables and stream buffers to clean zero state for presentations and tests.
    Bumps reset_epoch so a running stream processor notices the reset and clears its
    in-memory window / counters instead of writing the old totals back."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM network_readings;")
    cursor.execute("""
    UPDATE network_metrics SET
        last_updated = datetime('now'),
        current_kbps = 0.0,
        rolling_avg_kbps = 0.0,
        peak_kbps = 0.0,
        total_events = 0,
        total_anomalies = 0,
        threat_level = 'NORMAL',
        recent_anomaly_rate = 0.0,
        transport_mode = 'local',
        ml_latency_us = 0.0,
        reset_epoch = COALESCE(reset_epoch, 0) + 1
    WHERE metric_id = 1;
    """)
    conn.commit()
    conn.close()

    # Clear stream buffer if present
    buffer_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'stream_buffer.jsonl')
    if os.path.exists(buffer_file):
        try:
            with open(buffer_file, 'w', encoding='utf-8') as f:
                f.truncate(0)
        except Exception:
            pass

def insert_reading(data, db_path=DATABASE_PATH):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO network_readings (
        timestamp, src_ip, dst_port, protocol, packet_count, byte_count,
        duration_sec, syn_ratio, throughput_kbps, rolling_avg_kbps,
        is_anomaly, anomaly_score, attack_type
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        data['timestamp'],
        data.get('src_ip', '0.0.0.0'),
        int(data.get('dst_port', 0)),
        data.get('protocol', 'TCP'),
        int(data.get('packet_count', 0)),
        int(data.get('byte_count', 0)),
        float(data.get('duration_sec', 0.0)),
        float(data.get('syn_ratio', 0.0)),
        float(data.get('throughput_kbps', 0.0)),
        float(data.get('rolling_avg_kbps', 0.0)),
        int(data.get('is_anomaly', 0)),
        float(data.get('anomaly_score', 0.0)),
        data.get('attack_type', 'Benign')
    ))
    conn.commit()
    conn.close()

def update_metrics(data, db_path=DATABASE_PATH):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE network_metrics SET
        last_updated = ?,
        current_kbps = ?,
        rolling_avg_kbps = ?,
        peak_kbps = ?,
        total_events = ?,
        total_anomalies = ?,
        threat_level = ?,
        recent_anomaly_rate = ?,
        transport_mode = ?,
        ml_latency_us = ?
    WHERE metric_id = 1;
    """, (
        data.get('last_updated', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
        float(data.get('current_kbps', 0.0)),
        float(data.get('rolling_avg_kbps', 0.0)),
        float(data.get('peak_kbps', 0.0)),
        int(data.get('total_events', 0)),
        int(data.get('total_anomalies', 0)),
        data.get('threat_level', 'NORMAL'),
        float(data.get('recent_anomaly_rate', 0.0)),
        data.get('transport_mode', 'local'),
        float(data.get('ml_latency_us', 0.0))
    ))
    conn.commit()
    conn.close()

_READING_COLS = (
    "timestamp", "src_ip", "dst_port", "protocol", "packet_count", "byte_count",
    "duration_sec", "syn_ratio", "throughput_kbps", "rolling_avg_kbps",
    "is_anomaly", "anomaly_score", "attack_type", "is_attack_ground_truth"
)

def persist_batch(readings, metrics_record, db_path=DATABASE_PATH):
    """Persist a whole poll-batch of scored readings plus one metrics snapshot in a
    single WAL transaction. One connection / one commit per batch keeps the serving
    layer's write cost off the per-event critical path."""
    if not readings and not metrics_record:
        return
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    if readings:
        rows = [
            (
                r["timestamp"], r.get("src_ip", "0.0.0.0"), int(r.get("dst_port", 0)),
                r.get("protocol", "TCP"), int(r.get("packet_count", 0)), int(r.get("byte_count", 0)),
                float(r.get("duration_sec", 0.0)), float(r.get("syn_ratio", 0.0)),
                float(r.get("throughput_kbps", 0.0)), float(r.get("rolling_avg_kbps", 0.0)),
                int(r.get("is_anomaly", 0)), float(r.get("anomaly_score", 0.0)),
                r.get("attack_type", "Benign"), int(r.get("is_attack_ground_truth", 0)),
            )
            for r in readings
        ]
        cursor.executemany(
            f"INSERT INTO network_readings ({', '.join(_READING_COLS)}) "
            f"VALUES ({', '.join(['?'] * len(_READING_COLS))});",
            rows,
        )
    if metrics_record:
        d = metrics_record
        cursor.execute("""
        UPDATE network_metrics SET
            last_updated = ?, current_kbps = ?, rolling_avg_kbps = ?, peak_kbps = ?,
            total_events = ?, total_anomalies = ?, threat_level = ?, recent_anomaly_rate = ?,
            transport_mode = ?, ml_latency_us = ?
        WHERE metric_id = 1;
        """, (
            d.get("last_updated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            float(d.get("current_kbps", 0.0)), float(d.get("rolling_avg_kbps", 0.0)),
            float(d.get("peak_kbps", 0.0)), int(d.get("total_events", 0)),
            int(d.get("total_anomalies", 0)), d.get("threat_level", "NORMAL"),
            float(d.get("recent_anomaly_rate", 0.0)), d.get("transport_mode", "local"),
            float(d.get("ml_latency_us", 0.0)),
        ))
    conn.commit()
    conn.close()

def get_reset_epoch(db_path=DATABASE_PATH):
    """Current reset counter; changes every time reset_db() runs."""
    conn = get_db_connection(db_path)
    row = conn.execute("SELECT reset_epoch FROM network_metrics WHERE metric_id = 1").fetchone()
    conn.close()
    return int(row[0] or 0) if row else 0

def get_latest_metrics(db_path=DATABASE_PATH):
    conn = get_db_connection(db_path)
    df = pd.read_sql("SELECT * FROM network_metrics WHERE metric_id = 1", conn)
    conn.close()
    if df.empty:
        return {}
    return df.iloc[0].to_dict()

def get_recent_readings(limit=100, db_path=DATABASE_PATH):
    conn = get_db_connection(db_path)
    df = pd.read_sql(f"""
    SELECT reading_pk, timestamp, src_ip, dst_port, protocol,
           packet_count, byte_count, throughput_kbps, rolling_avg_kbps,
           is_anomaly, anomaly_score, attack_type
    FROM network_readings
    ORDER BY reading_pk DESC
    LIMIT {limit};
    """, conn)
    conn.close()
    if not df.empty:
        df = df.iloc[::-1].reset_index(drop=True)
    return df

def get_attack_breakdown(db_path=DATABASE_PATH):
    conn = get_db_connection(db_path)
    df = pd.read_sql("""
    SELECT attack_type, COUNT(*) as count
    FROM network_readings
    WHERE is_anomaly = 1
    GROUP BY attack_type;
    """, conn)
    conn.close()
    return df

if __name__ == '__main__':
    init_db()
    print("[+] Database initialized with WAL mode successfully.")

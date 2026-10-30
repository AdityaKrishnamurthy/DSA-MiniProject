"""
run.py
One entry point for the whole project.

    python run.py            live demo: the first DDoS attack arrives after ~10 seconds
    python run.py full       live replay of the whole dataset from the first flow
    python run.py test       automated end-to-end test (120 flows through a DDoS burst)
    python run.py train      regenerate the dataset and retrain the ML model
    python run.py serve      non-interactive mode used inside the Docker container

While the stream runs:  P = pause / resume (freeze test)   Q = stop everything.

Kafka: if Docker Desktop is running, the Kafka service from docker-compose.yml is started
automatically (docker compose up -d kafka) and the pipeline streams through it. Without Docker the pipeline uses its
local fallback channel (add --no-kafka to skip the Docker check).
"""
import argparse
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import webbrowser

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
os.chdir(BASE_DIR)   # so Streamlit picks up .streamlit/config.toml

from src.config import DATASET_PATH, MODEL_PATH, KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC
from src.database import init_db, reset_db, get_latest_metrics, get_recent_readings
from src.producer import run_producer
from src.processor import run_processor
from src.stream_broker import is_kafka_online

DASHBOARD_PORT = 8501
DASHBOARD_URL = f"http://localhost:{DASHBOARD_PORT}"
DEMO_START_ROW = 550        # 50 flows (~10 s) before the first DDoS burst at row 600
DASHBOARD_LOG = os.path.join(BASE_DIR, "dashboard.log")


def banner(text):
    print("\n" + "=" * 65)
    print(f" {text}")
    print("=" * 65)


# ---------------------------------------------------------------- setup steps

def train():
    banner("GENERATING DATASET AND TRAINING THE ISOLATION FOREST MODEL")
    import data.generate_dataset as gen
    import models.train_model as trainer
    gen.generate_network_data()
    trainer.train_offline()
    print("[+] Training completed.")


def ensure_model():
    if not os.path.exists(DATASET_PATH) or not os.path.exists(MODEL_PATH):
        print("[*] Dataset or model missing - creating them first.")
        train()


def start_kafka():
    """Start the Kafka broker with Docker if possible; return True when it is ready."""
    if is_kafka_online():
        print(f"[+] Kafka broker already running on {KAFKA_BOOTSTRAP_SERVERS}.")
        return True
    if shutil.which("docker") is None:
        print("[!] Docker is not installed - using the local fallback channel instead of Kafka.")
        return False
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        print("[!] Docker Desktop is not running - start it to use Kafka.")
        print("    Continuing with the local fallback channel.")
        return False

    print("[*] Starting the Kafka broker (docker compose up -d kafka) ...")
    if subprocess.run(["docker", "compose", "up", "-d", "kafka"], cwd=BASE_DIR).returncode != 0:
        print("[!] 'docker compose up' failed - continuing with the local fallback channel.")
        return False
    if wait_for_kafka(90):
        return True
    print("[!] Kafka did not become ready in time - continuing with the local fallback channel.")
    return False


def wait_for_kafka(timeout):
    """The port opens a few seconds before the broker can serve requests; wait until it can."""
    from kafka import KafkaAdminClient
    print(f"[*] Waiting for Kafka on {KAFKA_BOOTSTRAP_SERVERS}", end="", flush=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if is_kafka_online():
                admin = KafkaAdminClient(bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS, request_timeout_ms=3000)
                admin.list_topics()
                admin.close()
                print(f"\n[+] Kafka is ready on {KAFKA_BOOTSTRAP_SERVERS} (topic '{KAFKA_TOPIC}').")
                return True
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(2)
    print()
    return False


def free_dashboard_port():
    """Stop an old dashboard that is still holding the port (e.g. from a previous run)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex(("127.0.0.1", DASHBOARD_PORT)) != 0:
            return
    if sys.platform != "win32":
        return
    out = subprocess.run(f"netstat -ano | findstr :{DASHBOARD_PORT}", shell=True,
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[3] == "LISTENING" and parts[-1].isdigit():
            pid = parts[-1]
            image = subprocess.run(f'tasklist /FI "PID eq {pid}" /NH', shell=True,
                                   capture_output=True, text=True).stdout.lower()
            if "python" in image or "streamlit" in image:
                subprocess.run(f"taskkill /F /PID {pid}", shell=True, capture_output=True)
                print(f"[*] Stopped an old dashboard process (PID {pid}).")
            else:
                print(f"[!] Port {DASHBOARD_PORT} is used by another program - probably the Docker dashboard.")
                print("    Stop it with 'docker compose down' (or 'docker compose stop app') and try again.")
                sys.exit(1)
    time.sleep(1)


def start_dashboard():
    free_dashboard_port()
    log = open(DASHBOARD_LOG, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", "dashboard/app.py", f"--server.port={DASHBOARD_PORT}"],
        cwd=BASE_DIR, stdout=log, stderr=subprocess.STDOUT,
    )
    for _ in range(40):                       # wait up to ~20 s for Streamlit to listen
        if proc.poll() is not None:
            break
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", DASHBOARD_PORT)) == 0:
                break
        time.sleep(0.5)
    if proc.poll() is not None:
        print(f"[!] The dashboard failed to start - see {DASHBOARD_LOG}")
        sys.exit(1)
    print(f"[+] Dashboard running at {DASHBOARD_URL}  (log: dashboard.log)")
    webbrowser.open(DASHBOARD_URL)
    return proc


# ---------------------------------------------------------------- live stream

def wait_for_keys(paused, stop, producer_thread):
    """P toggles pause, Q (or Ctrl+C) stops. Returns when the stream should end."""
    try:
        import msvcrt
    except ImportError:
        msvcrt = None
    try:
        while producer_thread.is_alive():
            if msvcrt is not None and msvcrt.kbhit():
                key = msvcrt.getwch().lower()
                if key == "p":
                    if paused.is_set():
                        paused.clear()
                        print("\n>>> RESUMED - events are flowing again.\n")
                    else:
                        paused.set()
                        print("\n>>> PAUSED - no new events. The dashboard keeps refreshing but every number "
                              "stays frozen. Press P to resume.\n")
                elif key == "q":
                    break
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    stop.set()
    paused.clear()


def live(start_row, use_kafka):
    ensure_model()
    banner("REAL-TIME NETWORK THREAT DETECTION - LIVE STREAMING PIPELINE")
    if use_kafka:
        start_kafka()
    else:
        print("[*] --no-kafka given: using the local fallback channel.")

    init_db()
    reset_db()
    print("[+] Database reset - all dashboard counters start at zero.")

    dashboard = start_dashboard()

    threading.Thread(target=run_processor, daemon=True).start()
    time.sleep(2)   # let the consumer attach before the first event is published

    paused, stop = threading.Event(), threading.Event()
    producer = threading.Thread(
        target=run_producer,
        kwargs=dict(pacing_delay=0.2, loop=True, start_row=start_row, paused=paused, stop=stop, verbose=False),
        daemon=True,
    )
    producer.start()

    banner("STREAMING  |  P = pause / resume (freeze test)   Q = stop")
    if start_row:
        print("The first DDoS attack reaches the dashboard in about 10 seconds.\n")
    wait_for_keys(paused, stop, producer)

    print("\n[*] Stopping the pipeline ...")
    producer.join(timeout=5)
    dashboard.terminate()
    try:
        dashboard.wait(timeout=5)
    except subprocess.TimeoutExpired:
        dashboard.kill()
    print("[+] Pipeline stopped. (The Kafka container keeps running; 'docker compose down' stops it.)")


# ---------------------------------------------------------------- automated test

def test(use_kafka):
    ensure_model()
    banner("AUTOMATED END-TO-END TEST")
    if use_kafka:
        start_kafka()

    # Rows 570-689: 30 normal flows, then the first 90 flows of the first DDoS burst.
    start_row, n_events = 570, 120
    init_db()
    reset_db()

    proc = threading.Thread(target=run_processor, kwargs={"max_events": n_events}, daemon=True)
    proc.start()
    time.sleep(2)
    run_producer(max_events=n_events, pacing_delay=0.02, loop=False, start_row=start_row, verbose=False)
    proc.join(timeout=20)

    metrics = get_latest_metrics()
    readings = get_recent_readings(limit=200)
    burst = readings.iloc[30:]
    flagged = int(burst["is_anomaly"].sum())

    banner("RESULTS")
    print(f"Transport used:          {metrics.get('transport_mode')}")
    print(f"Events processed:        {metrics.get('total_events', 0)} / {n_events}")
    print(f"Peak throughput:         {metrics.get('peak_kbps', 0.0):,.1f} KB/s")
    print(f"Anomalies flagged:       {metrics.get('total_anomalies', 0)}")
    print(f"DDoS burst flows caught: {flagged} / {len(burst)}")
    print(f"Threat level:            {metrics.get('threat_level')}")

    checks = [
        ("all events processed", metrics.get("total_events", 0) == n_events and len(readings) == n_events),
        ("DDoS spike seen (> 200 KB/s)", metrics.get("peak_kbps", 0.0) > 200.0),
        (">= 90 % of burst flows flagged", flagged >= 0.9 * len(burst)),
        ("flagged burst flows labelled DDoS", (burst.loc[burst["is_anomaly"] == 1, "attack_type"] == "DDoS_Volumetric").all()),
        ("threat level reached CRITICAL ATTACK", metrics.get("threat_level") == "CRITICAL ATTACK"),
    ]
    reset_db()
    checks.append(("reset clears the database",
                   get_latest_metrics().get("total_events", -1) == 0 and get_recent_readings(limit=5).empty))

    print()
    for name, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if all(ok for _, ok in checks):
        print("\n[SUCCESS] All checks passed.")
        return 0
    print("\n[FAILED] At least one check failed.")
    return 1


# ---------------------------------------------------------------- Docker container

def serve():
    """Non-interactive run inside Docker: wait for Kafka, then dashboard + processor + producer."""
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))   # 'docker compose down' stops cleanly
    ensure_model()
    banner("REAL-TIME NETWORK THREAT DETECTION - DOCKER")
    if not wait_for_kafka(120):
        print("[!] Kafka is not reachable - streaming over the local fallback channel instead.")
    init_db()
    reset_db()

    dashboard = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", "dashboard/app.py",
         f"--server.port={DASHBOARD_PORT}", "--server.address=0.0.0.0"],
        cwd=BASE_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
    )
    print(f"[+] Dashboard: open {DASHBOARD_URL} in your browser.")
    threading.Thread(target=run_processor, daemon=True).start()
    time.sleep(2)
    try:
        run_producer(pacing_delay=0.2, loop=True, start_row=DEMO_START_ROW, verbose=False)
    finally:
        dashboard.terminate()


def main():
    parser = argparse.ArgumentParser(description="Real-time network threat detection pipeline")
    parser.add_argument("mode", nargs="?", default="demo", choices=["demo", "full", "test", "train", "serve"],
                        help="demo (default): start just before the first DDoS attack; "
                             "full: replay from the first flow; test: automated check; train: retrain the model")
    parser.add_argument("--no-kafka", action="store_true", help="do not start/use Kafka; use the local fallback channel")
    args = parser.parse_args()
    use_kafka = not args.no_kafka
    if args.no_kafka:
        os.environ["SOC_DISABLE_KAFKA"] = "1"     # is_kafka_online() then always says no

    if args.mode == "train":
        train()
    elif args.mode == "serve":
        serve()
    elif args.mode == "test":
        sys.exit(test(use_kafka))
    else:
        live(DEMO_START_ROW if args.mode == "demo" else 0, use_kafka)


if __name__ == "__main__":
    main()

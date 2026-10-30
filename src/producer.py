"""
src/producer.py
Layers 1 & 2: Paced Stream Producer.
Reads timestamped network flow telemetry from CSV and publishes events to the streaming topic.
Paced transmission (5 events/sec) turns a static dataset into a realistic live stream.
"""
import csv
import time
import sys
import os
from src.config import DATASET_PATH, PACING_DELAY, KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC
from src.stream_broker import StreamEventProducer

def run_producer(dataset_path=DATASET_PATH, pacing_delay=PACING_DELAY, max_events=None, loop=True, start_row=0,
                 paused=None, stop=None, verbose=True):
    """paused / stop are optional threading.Event objects: while 'paused' is set no events
    are sent (the dashboard freezes), and setting 'stop' ends the stream."""
    print("=" * 65)
    print(" [LAYER 1 & 2] STARTING PACED NETWORK TELEMETRY PRODUCER")
    print(f" Source CSV: {dataset_path}")
    print(f" Pacing Delay: {pacing_delay}s (~{1/pacing_delay:.1f} events/sec)")
    print(f" Streaming Topic: '{KAFKA_TOPIC}'")
    print("=" * 65)

    if not os.path.exists(dataset_path):
        print(f"[!] Dataset not found at {dataset_path}. Run 'python data/generate_dataset.py' first.")
        sys.exit(1)

    producer = StreamEventProducer()
    event_count = 0

    try:
        while True:
            with open(dataset_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row_idx, row in enumerate(reader):
                    if row_idx < start_row:
                        continue
                    # Clean and cast fields
                    try:
                        event = {
                            'timestamp': row['timestamp'],
                            'src_ip': row['src_ip'],
                            'dst_port': int(row['dst_port']),
                            'protocol': row['protocol'],
                            'packet_count': int(row['packet_count']),
                            'byte_count': int(row['byte_count']),
                            'duration_sec': float(row['duration_sec']),
                            'syn_ratio': float(row['syn_ratio']),
                            'attack_type': row.get('attack_type', 'Benign'),
                            'is_attack_ground_truth': int(row.get('is_attack_ground_truth', 0))
                        }
                    except (ValueError, KeyError) as err:
                        # Guard against corrupted rows
                        continue

                    while paused is not None and paused.is_set():
                        if stop is not None and stop.is_set():
                            return
                        time.sleep(0.1)
                    if stop is not None and stop.is_set():
                        return

                    # Send to stream broker
                    producer.send(event)
                    event_count += 1

                    # Log live progress periodically
                    if verbose and (event_count % 10 == 0 or event['is_attack_ground_truth'] == 1):
                        status = f"[ATTACK: {event['attack_type']}]" if event['is_attack_ground_truth'] == 1 else "[NORMAL]"
                        print(f"-> Produced #{event_count:05d} | {event['timestamp']} | {event['src_ip']} -> :{event['dst_port']} ({event['protocol']}) | {event['byte_count']/1024:.1f} KB {status}")

                    if max_events and event_count >= max_events:
                        print(f"[+] Reached target {max_events} events. Producer stopping.")
                        return

                    time.sleep(pacing_delay)

            if not loop:
                break
            start_row = 0          # later passes replay the whole file
            print("[*] Reached end of dataset. Looping from start for continuous streaming...")

    except KeyboardInterrupt:
        print("\n[*] Producer stopped by user.")
    finally:
        producer.flush()
        producer.close()
        print(f"[+] Producer finished. Total events sent: {event_count}")

if __name__ == '__main__':
    run_producer()

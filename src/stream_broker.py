"""
src/stream_broker.py
Transport abstraction for the event stream.
Connects to Apache Kafka (localhost:9092) when a broker is reachable; otherwise
falls back to a single resilient local channel - a line-delimited JSONL buffer
(stream_buffer.jsonl) with per-consumer offset tracking - that mirrors Kafka
publish/subscribe semantics for both single-process and multi-terminal runs.
"""
import json
import time
import os
import socket

try:
    from kafka import KafkaProducer, KafkaConsumer, TopicPartition
    from kafka.admin import KafkaAdminClient, NewTopic
    from kafka.errors import KafkaError, TopicAlreadyExistsError
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    KafkaError = Exception

from src.config import KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC

_FALLBACK_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'stream_buffer.jsonl')

# When the local fallback buffer file grows past this size, the consumer rewrites
# it to keep only the still-unconsumed tail so a long demo cannot fill the disk.
_FALLBACK_TRIM_BYTES = 8 * 1024 * 1024

def is_kafka_online(bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS):
    if not KAFKA_AVAILABLE or os.getenv('SOC_DISABLE_KAFKA') == '1':
        return False
    try:
        host, port = bootstrap_servers.split(':')
        with socket.create_connection((host, int(port)), timeout=0.3):
            return True
    except Exception:
        return False

def ensure_topic(bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS, topic=KAFKA_TOPIC):
    """Create the topic once if it does not exist yet, so the consumer gets a partition
    assignment immediately instead of waiting for a metadata refresh."""
    try:
        admin = KafkaAdminClient(bootstrap_servers=bootstrap_servers, client_id='soc-admin')
        try:
            if topic not in admin.list_topics():
                admin.create_topics([NewTopic(name=topic, num_partitions=1, replication_factor=1)])
                print(f"[+] Created Kafka topic '{topic}'")
        finally:
            admin.close()
    except TopicAlreadyExistsError:
        pass
    except Exception as e:
        print(f"[!] Could not verify Kafka topic '{topic}' ({e}); relying on broker auto-creation.")

class StreamEventProducer:
    def __init__(self, bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS, topic=KAFKA_TOPIC):
        self.topic = topic
        self.mode = 'kafka' if is_kafka_online(bootstrap_servers) else 'local'
        self.producer = None

        if self.mode == 'kafka':
            try:
                ensure_topic(bootstrap_servers, topic)
                self.producer = KafkaProducer(
                    bootstrap_servers=bootstrap_servers,
                    value_serializer=lambda v: json.dumps(v).encode('utf-8')
                )
                print(f"[+] Connected to Apache Kafka Broker on {bootstrap_servers}")
            except Exception as e:
                print(f"[!] Error initializing Kafka Producer ({e}). Activating resilient local stream broker.")
                self.mode = 'local'
        else:
            print(f"[*] Kafka broker offline on {bootstrap_servers}. Using resilient local streaming channel (Kafka semantics).")

    def send(self, event_dict):
        if self.mode == 'kafka' and self.producer:
            try:
                self.producer.send(self.topic, value=event_dict)
                return True
            except Exception as e:
                print(f"[!] Error sending to Kafka: {e}. Falling back to local buffer.")
                self.mode = 'local'

        # Local channel: append one JSON line to the shared buffer file.
        try:
            with open(_FALLBACK_FILE, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event_dict) + '\n')
        except Exception:
            pass
        return True

    def flush(self):
        if self.mode == 'kafka' and self.producer:
            try:
                self.producer.flush()
            except Exception:
                pass

    def close(self):
        if self.mode == 'kafka' and self.producer:
            try:
                self.producer.close()
            except Exception:
                pass


class StreamEventConsumer:
    def __init__(self, bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS, topic=KAFKA_TOPIC):
        self.topic = topic
        self.mode = 'kafka' if is_kafka_online(bootstrap_servers) else 'local'
        self.consumer = None
        self._file_offset = 0

        if self.mode == 'kafka':
            try:
                ensure_topic(bootstrap_servers, topic)
                self.consumer = KafkaConsumer(
                    bootstrap_servers=bootstrap_servers,
                    auto_offset_reset='latest',
                    enable_auto_commit=False,
                    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
                )
                # Assign the topic's partitions directly and pin the read position to the
                # current end NOW, so every event published after this point is received
                # (a lazily resolved 'latest' offset could skip the first events).
                partitions = None
                deadline = time.time() + 15
                while not partitions and time.time() < deadline:
                    partitions = self.consumer.partitions_for_topic(topic)
                    if not partitions:
                        time.sleep(0.5)
                if not partitions:
                    raise RuntimeError(f"no partitions found for topic '{topic}'")
                tps = [TopicPartition(topic, p) for p in sorted(partitions)]
                self.consumer.assign(tps)
                self.consumer.seek_to_end(*tps)
                for tp in tps:
                    self.consumer.position(tp)
                print(f"[+] Consumer attached to Apache Kafka topic '{topic}'")
            except Exception as e:
                print(f"[!] Error initializing Kafka Consumer ({e}). Activating resilient local stream consumer.")
                self.mode = 'local'
        else:
            print(f"[*] Kafka broker offline on {bootstrap_servers}. Using resilient local stream consumer.")

        if self.mode == 'local' and os.path.exists(_FALLBACK_FILE):
            # Start from the current end of the buffer: only consume events
            # published from now on (mirrors Kafka auto_offset_reset='latest').
            self._file_offset = os.path.getsize(_FALLBACK_FILE)

    def poll_events(self, timeout_ms=500):
        if self.mode == 'kafka' and self.consumer:
            try:
                msg_pack = self.consumer.poll(timeout_ms=timeout_ms)
                events = []
                for tp, messages in msg_pack.items():
                    for msg in messages:
                        events.append(msg.value)
                return events
            except Exception as e:
                print(f"[!] Kafka poll error ({e}). Switching to resilient local consumer.")
                self.mode = 'local'
                if os.path.exists(_FALLBACK_FILE):
                    self._file_offset = os.path.getsize(_FALLBACK_FILE)

        # Local polling: read newly appended lines from the shared buffer file.
        events = []
        if os.path.exists(_FALLBACK_FILE):
            try:
                if os.path.getsize(_FALLBACK_FILE) < self._file_offset:
                    # The buffer was truncated (dashboard / CLI reset): start again from
                    # the beginning instead of seeking past the end and missing events.
                    self._file_offset = 0
                with open(_FALLBACK_FILE, 'rb') as f:
                    f.seek(self._file_offset)
                    chunk = f.read()
                # Only consume complete lines; a line the producer is still writing is
                # picked up on the next poll instead of being dropped as invalid JSON.
                end = chunk.rfind(b'\n') + 1
                self._file_offset += end
                for raw in chunk[:end].splitlines():
                    line = raw.decode('utf-8', errors='replace').strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except Exception:
                            pass
                self._maybe_trim_buffer()
            except Exception:
                pass

        if not events and timeout_ms > 0:
            time.sleep(min(timeout_ms / 1000.0, 0.05))

        return events

    def _maybe_trim_buffer(self):
        """Rewrite the fallback JSONL buffer to keep only the unconsumed tail once it grows large."""
        try:
            if self._file_offset < _FALLBACK_TRIM_BYTES:
                return
            with open(_FALLBACK_FILE, 'r+b') as f:
                f.seek(self._file_offset)
                remainder = f.read()          # any lines appended since the last read
                f.seek(0)
                f.truncate()
                f.write(remainder)
            self._file_offset = 0
        except Exception:
            pass

    def close(self):
        if self.mode == 'kafka' and self.consumer:
            try:
                self.consumer.close()
            except Exception:
                pass

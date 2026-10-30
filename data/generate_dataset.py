"""
data/generate_dataset.py
Generates a realistic, continuous network telemetry dataset (data/network_traffic.csv)
containing baseline enterprise traffic interleaved with realistic cybersecurity attack patterns.
"""
import os
import csv
import random
from datetime import datetime, timedelta

def generate_network_data(output_file='data/network_traffic.csv', num_events=8000, seed=42):
    random.seed(seed)
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    start_time = datetime(2026, 9, 7, 8, 0, 0)
    
    # Internal & External IP pools
    normal_internal_ips = [f"192.168.1.{i}" for i in range(10, 150)]
    normal_servers = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]
    external_normal_ips = [f"203.0.113.{i}" for i in range(1, 100)] + [f"198.51.100.{i}" for i in range(1, 100)]
    attacker_botnet_ips = [f"185.220.101.{i}" for i in range(1, 50)] + [f"45.33.32.{i}" for i in range(1, 50)]

    fieldnames = [
        'timestamp', 'src_ip', 'dst_port', 'protocol', 
        'packet_count', 'byte_count', 'duration_sec', 'syn_ratio', 
        'attack_type', 'is_attack_ground_truth'
    ]

    events = []
    current_time = start_time
    
    # Define attack clusters (bursts) to make streaming curves feel authentic
    attack_intervals = [
        (600, 700, 'DDoS_Volumetric'),
        (1400, 1480, 'SYN_Flood'),
        (2200, 2320, 'Port_Scan'),
        (3300, 3450, 'DDoS_Volumetric'),
        (4500, 4580, 'SYN_Flood'),
        (5600, 5750, 'DDoS_Volumetric'),
        (6800, 6900, 'Port_Scan')
    ]

    def get_active_attack(idx):
        for start, end, atype in attack_intervals:
            if start <= idx <= end:
                return atype
        return None

    for i in range(num_events):
        current_time += timedelta(seconds=1)
        time_str = current_time.strftime('%Y-%m-%d %H:%M:%S')

        active_attack = get_active_attack(i)

        if active_attack == 'DDoS_Volumetric':
            # Severe volumetric flood
            src_ip = random.choice(attacker_botnet_ips)
            dst_port = random.choice([80, 443, 8080])
            protocol = random.choice(['TCP', 'UDP'])
            packet_count = random.randint(400, 2200)
            byte_count = packet_count * random.randint(700, 1450) # massive bytes (300KB - 3MB)
            duration_sec = round(random.uniform(0.1, 0.6), 3)
            syn_ratio = round(random.uniform(0.1, 0.4), 3)
            attack_type = 'DDoS_Volumetric'
            is_attack = 1

        elif active_attack == 'SYN_Flood':
            # TCP SYN flood attack
            src_ip = random.choice(attacker_botnet_ips)
            dst_port = random.choice([80, 443])
            protocol = 'TCP'
            packet_count = random.randint(150, 800)
            byte_count = packet_count * 64 # Small SYN packets
            duration_sec = round(random.uniform(0.01, 0.25), 3)
            syn_ratio = round(random.uniform(0.85, 1.0), 3) # Extremely high SYN ratio
            attack_type = 'SYN_Flood'
            is_attack = 1

        elif active_attack == 'Port_Scan':
            # Stealthy port scanning probe
            src_ip = random.choice(attacker_botnet_ips)
            dst_port = random.randint(20, 1024)
            protocol = 'TCP'
            packet_count = random.randint(1, 4)
            byte_count = packet_count * random.randint(40, 60)
            duration_sec = round(random.uniform(0.005, 0.05), 3)
            syn_ratio = 1.0
            attack_type = 'Port_Scan'
            is_attack = 1

        else:
            # Normal baseline traffic
            traffic_category = random.choices(['web', 'dns', 'ssh', 'api'], weights=[0.55, 0.20, 0.10, 0.15])[0]

            if traffic_category == 'web':
                src_ip = random.choice(normal_internal_ips + external_normal_ips)
                dst_port = random.choice([80, 443])
                protocol = 'TCP'
                packet_count = random.randint(8, 45)
                byte_count = packet_count * random.randint(200, 1100) # 2KB - 50KB
                duration_sec = round(random.uniform(0.2, 3.5), 3)
                syn_ratio = round(random.uniform(0.02, 0.15), 3)

            elif traffic_category == 'dns':
                src_ip = random.choice(normal_internal_ips)
                dst_port = 53
                protocol = 'UDP'
                packet_count = random.randint(1, 3)
                byte_count = random.randint(64, 320)
                duration_sec = round(random.uniform(0.01, 0.08), 3)
                syn_ratio = 0.0

            elif traffic_category == 'ssh':
                src_ip = random.choice(normal_internal_ips)
                dst_port = 22
                protocol = 'TCP'
                packet_count = random.randint(20, 80)
                byte_count = packet_count * random.randint(150, 400)
                duration_sec = round(random.uniform(1.0, 12.0), 3)
                syn_ratio = round(random.uniform(0.01, 0.05), 3)

            else: # api
                src_ip = random.choice(normal_internal_ips + external_normal_ips)
                dst_port = 8080
                protocol = 'TCP'
                packet_count = random.randint(5, 25)
                byte_count = packet_count * random.randint(300, 800)
                duration_sec = round(random.uniform(0.1, 1.5), 3)
                syn_ratio = round(random.uniform(0.04, 0.12), 3)

            attack_type = 'Benign'
            is_attack = 0

        events.append({
            'timestamp': time_str,
            'src_ip': src_ip,
            'dst_port': dst_port,
            'protocol': protocol,
            'packet_count': packet_count,
            'byte_count': byte_count,
            'duration_sec': duration_sec,
            'syn_ratio': syn_ratio,
            'attack_type': attack_type,
            'is_attack_ground_truth': is_attack
        })

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)

    print(f"Generated {len(events)} network flow events successfully saved to {output_file}")
    attack_count = sum(1 for e in events if e['is_attack_ground_truth'] == 1)
    print(f"Total Attacks: {attack_count} ({attack_count / len(events) * 100:.2f}%)")

if __name__ == '__main__':
    generate_network_data()

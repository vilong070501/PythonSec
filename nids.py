import os
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time
import logging

# Configuration de journalisation
OPENCANARY_INTERFACE = "lo"
ALERT_LOG_FILE = "nids_alerts.log"
BLOCKED_IPS = set()


logging.basicConfig(filename=ALERT_LOG_FILE, level=logging.INFO)

# Dictionnaire pour suivre les tentatives de connexion
connection_attempts = defaultdict(list)

# Fonction pour bloquer une IP
def block_ip(ip):
    if ip not in BLOCKED_IPS:
        try:
            print(f"Blocking IP: {ip}")
            os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
            BLOCKED_IPS.add(ip)
            print(BLOCKED_IPS)
            logging.info(f"Blocked IP: {ip}")
        except Exception as e:
            logging.error(f"Error blocking IP {ip}: {e}")

# Fonction d'analyse de paquets
def analyze_packet(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        print(f"Packet: {src_ip} -> {dst_ip}:{dst_port}")
        detect_anomalies(src_ip, dst_port)

# Détection d'anomalies
def detect_anomalies(src_ip, dst_port):
    timestamp = time.time()
    connection_attempts[src_ip].append((dst_port, timestamp))
    connection_attempts[src_ip] = [
        (port, ts) for port, ts in connection_attempts[src_ip] if timestamp - ts <= 60
    ]
    if len(connection_attempts[src_ip]) > 20:
        alert(f"[ALERT] Port Scan detected from {src_ip}")
        block_ip(src_ip)

    if sum(1 for port, _ in connection_attempts[src_ip] if port == dst_port) > 10:
        alert(f"[ALERT] Brute Force attack detected on port {dst_port} from {src_ip}")
        block_ip(src_ip)

# Fonction d'alerte
def alert(message):
    print(message)
    logging.info(message)

# Capture de paquets
def capture_packets():
    sniff(prn=analyze_packet, store=False)

if __name__ == "__main__":
    try:
        capture_packets()
    except KeyboardInterrupt:
        print("Packet capture stopped.")
    except Exception as e:
        logging.error(f"Error during packet capture: {e}")

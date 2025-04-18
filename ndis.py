import os
from scapy.all import sniff, IP, TCP, ARP
from collections import defaultdict, Counter
import time
import logging

# Configuration de journalisation
OPENCANARY_INTERFACE = "lo"
ALERT_LOG_FILE = "nids_alerts.log"
BLOCKED_IPS = set()
logging.basicConfig(filename=ALERT_LOG_FILE, level=logging.INFO)

# Dictionnaire pour suivre les tentatives de connexion et les paquets
connection_attempts = defaultdict(list)
ddos_traffic = defaultdict(list)
arp_table = {}  # ARP cache pour détecter les empoisonnements ARP
scan_ports = {}

# Fonction pour bloquer une IP
def block_ip(ip):
    if ip not in BLOCKED_IPS:
        try:
            print(f"Blocking IP: {ip}")
            os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
            BLOCKED_IPS.add(ip)
            logging.info(f"Blocked IP: {ip}")
        except Exception as e:
            logging.error(f"Error blocking IP {ip}: {e}")

# Fonction d'alerte
def alert(message):
    print(message)
    logging.info(message)

ssh_attempts = defaultdict(list)

# Fonction pour détecter les attaques de force brute SSH
def detect_ssh_brute_force(src_ip):
    timestamp = time.time()
    ssh_attempts[src_ip].append(timestamp)
    ssh_attempts[src_ip] = [
        ts for ts in ssh_attempts[src_ip] if timestamp - ts <= 10  # Limiter à 10 secondes
    ]

    # Si plus de 5 tentatives dans les 10 dernières secondes, c'est une attaque
    if len(ssh_attempts[src_ip]) > 6:  # Seuil de force brute SSH
        alert(f"[ALERT] Possible SSH brute-force attack detected from {src_ip}")
        block_ip(src_ip)
ftp_attempts = defaultdict(list)

def detect_ftp_brute_force(src_ip):
    timestamp = time.time()
    ftp_attempts[src_ip].append(timestamp)
    ftp_attempts[src_ip] = [
        ts for ts in ftp_attempts[src_ip] if timestamp - ts <= 10  # Limiter à 60 secondes
    ]

    # Si plus de 5 tentatives de connexion échouées dans les 60 dernières secondes, c'est une attaque
    if len(ftp_attempts[src_ip]) > 8:  # Seuil de brute force FTP
        alert(f"[ALERT] Possible FTP brute-force attack detected from {src_ip}")
        block_ip(src_ip)

mysql_attempts = defaultdict(list)
def detect_mysql_brute_force(src_ip):
    timestamp = time.time()
    mysql_attempts[src_ip].append(timestamp)
    mysql_attempts[src_ip] = [
        ts for ts in mysql_attempts[src_ip] if timestamp - ts <= 10  # Limiter à 60 secondes
    ]

    # Si plus de 5 tentatives de connexion échouées dans les 60 dernières secondes, c'est une attaque
    if len(mysql_attempts[src_ip]) > 8:  # Seuil de brute force FTP
        alert(f"[ALERT] Possible MYSQL brute-force attack detected from {src_ip}")
        block_ip(src_ip)
# Détection de DDoS
def detect_ddos(src_ip, dst_ip):
    timestamp = time.time()
    ddos_traffic[src_ip].append(timestamp)
    ddos_traffic[src_ip] = [
        ts for ts in ddos_traffic[src_ip] if timestamp - ts <= 10
    ]

    if len(ddos_traffic[src_ip]) > 200:  # Seuil DDoS (ajustable)
        alert(f"[ALERT] Potential DDoS attack detected from {src_ip} targeting {dst_ip}")
        block_ip(src_ip)

# Détection de Scan de Ports
def detect_scan(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dport = packet[TCP].dport
        if src_ip not in scan_ports:
            scan_ports[src_ip] = set()
        scan_ports[src_ip].add(dport)
        if len(scan_ports[src_ip]) > 10:  # Seuil de détection
            print(f"Port scan detected from {src_ip}")
            block_ip(src_ip)

# Détection d'injection SQL
def detect_sql_injection(packet):
    if packet.haslayer(TCP) and packet.haslayer("Raw"):
        load = packet["Raw"].load.decode(errors='ignore')
        if "SELECT" in load or "UNION" in load or "DROP" in load:
            print(f"SQL Injection detected: {load}")
            block_ip(packet[IP].src)

# Analyse des paquets
def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if TCP in packet:
            dst_port = packet[TCP].dport
            print(f"Packet: {src_ip} -> {dst_ip}:{dst_port}")
            if dst_port == 22:
                detect_ssh_brute_force(src_ip)
            if dst_port == 21:
                detect_ftp_brute_force(src_ip)
            if dst_port == 3306:
                detect_mysql_brute_force(src_ip)
        detect_sql_injection(packet)
        detect_ddos(src_ip, dst_ip)
        detect_scan(packet)

# Capture des paquets
def capture_packets():
    sniff(prn=analyze_packet, store=False, iface=OPENCANARY_INTERFACE)

if __name__ == "__main__":
    try:
        capture_packets()
    except KeyboardInterrupt:
        print("Packet capture stopped.")
    except Exception as e:
        logging.error(f"Error during packet capture: {e}")


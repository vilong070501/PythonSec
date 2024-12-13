import os
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time
import logging

# Configuration des paramètres
OPENCANARY_INTERFACE = "lo"  # Interface réseau à surveiller
ALERT_LOG_FILE = "nids_alerts.log"  # Fichier de journalisation des alertes
BLOCKED_IPS = set()  # Ensemble des IP bloquées
logging.basicConfig(filename=ALERT_LOG_FILE, level=logging.INFO)

# Structures pour surveiller diverses activités malveillantes
ssh_attempts = defaultdict(list)  # Tentatives de force brute SSH
ftp_attempts = defaultdict(list)  # Tentatives de force brute FTP
mysql_attempts = defaultdict(list)  # Tentatives de force brute MySQL
ddos_traffic = defaultdict(list)  # Trafic suspecté de DDoS
scan_ports = {}  # Suivi des scans de ports

# Fonction pour bloquer une IP
def block_ip(ip):
    if ip not in BLOCKED_IPS:
        try:
            print(f"[ACTION] Blocking IP: {ip}")
            os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
            BLOCKED_IPS.add(ip)
            logging.info(f"Blocked IP: {ip}")
        except Exception as e:
            logging.error(f"Error blocking IP {ip}: {e}")

# Fonction pour journaliser et afficher une alerte
def alert(message):
    print(f"[ALERT] {message}")
    logging.info(message)

# Détection de force brute SSH
def detect_ssh_brute_force(src_ip):
    timestamp = time.time()
    ssh_attempts[src_ip].append(timestamp)
    ssh_attempts[src_ip] = [
        ts for ts in ssh_attempts[src_ip] if timestamp - ts <= 10  # Fenêtre de 10 secondes
    ]

    if len(ssh_attempts[src_ip]) > 6:  # Seuil de détection (6 tentatives en 10 secondes)
        alert(f"Possible SSH brute-force attack detected from {src_ip}")
        block_ip(src_ip)

# Détection de force brute FTP
def detect_ftp_brute_force(src_ip):
    timestamp = time.time()
    ftp_attempts[src_ip].append(timestamp)
    ftp_attempts[src_ip] = [
        ts for ts in ftp_attempts[src_ip] if timestamp - ts <= 10  # Fenêtre de 10 secondes
    ]

    if len(ftp_attempts[src_ip]) > 8:  # Seuil de détection (8 tentatives en 10 secondes)
        alert(f"Possible FTP brute-force attack detected from {src_ip}")
        block_ip(src_ip)

# Détection de force brute MySQL
def detect_mysql_brute_force(src_ip):
    timestamp = time.time()
    mysql_attempts[src_ip].append(timestamp)
    mysql_attempts[src_ip] = [
        ts for ts in mysql_attempts[src_ip] if timestamp - ts <= 10  # Fenêtre de 10 secondes
    ]

    if len(mysql_attempts[src_ip]) > 8:  # Seuil de détection (8 tentatives en 10 secondes)
        alert(f"Possible MySQL brute-force attack detected from {src_ip}")
        block_ip(src_ip)

# Détection d'attaques DDoS
def detect_ddos(src_ip, dst_ip):
    timestamp = time.time()
    ddos_traffic[src_ip].append(timestamp)
    ddos_traffic[src_ip] = [
        ts for ts in ddos_traffic[src_ip] if timestamp - ts <= 10  # Fenêtre de 10 secondes
    ]

    if len(ddos_traffic[src_ip]) > 200:  # Seuil de détection (200 paquets en 10 secondes)
        alert(f"Potential DDoS attack detected from {src_ip} targeting {dst_ip}")
        block_ip(src_ip)

# Détection de scan de ports
def detect_scan(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dport = packet[TCP].dport
        if src_ip not in scan_ports:
            scan_ports[src_ip] = set()
        scan_ports[src_ip].add(dport)
        if len(scan_ports[src_ip]) > 10:  # Seuil de détection (10 ports scannés)
            alert(f"Port scan detected from {src_ip}")
            block_ip(src_ip)

# Détection d'injection SQL
def detect_sql_injection(packet):
    if packet.haslayer(TCP) and packet.haslayer("Raw"):
        load = packet["Raw"].load.decode(errors='ignore')
        if "SELECT" in load or "UNION" in load or "DROP" in load:
            alert(f"SQL Injection detected: {load}")
            block_ip(packet[IP].src)

# Analyse des paquets capturés
def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if TCP in packet:
            dst_port = packet[TCP].dport
            print(f"[INFO] Packet: {src_ip} -> {dst_ip}:{dst_port}")
            if dst_port == 22:
                detect_ssh_brute_force(src_ip)
            elif dst_port == 21:
                detect_ftp_brute_force(src_ip)
            elif dst_port == 3306:
                detect_mysql_brute_force(src_ip)
        detect_sql_injection(packet)
        detect_ddos(src_ip, dst_ip)
        detect_scan(packet)

# Fonction principale pour capturer les paquets réseau
def capture_packets():
    sniff(prn=analyze_packet, store=False, iface=OPENCANARY_INTERFACE)

if __name__ == "__main__":
    try:
        print("[INFO] Starting packet capture...")
        capture_packets()
    except KeyboardInterrupt:
        print("[INFO] Packet capture stopped.")
    except Exception as e:
        logging.error(f"Error during packet capture: {e}")


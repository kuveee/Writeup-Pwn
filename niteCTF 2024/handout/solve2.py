#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


#p = process()
p = remote('mixed-signal.chals.nitectf2024.live', 1337, ssl=True)




p.interactive()

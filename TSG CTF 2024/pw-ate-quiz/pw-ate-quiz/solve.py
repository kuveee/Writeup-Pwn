#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./chall',checksec=False)

p = process()
gdb.attach(p,gdbscript='''
           brva 0x000000000000150C
           brva 0x000000000000165E
           brva 0x00000000000016F2
           brva 0x00000000000016BC
           ''')

p.sendlineafter(b'Enter the password > ',b'\x00'*31)
password = b''
key = b'0'
for i  in range(4,8):
    p.sendline(f'{i}'.encode())
    p.recvuntil(b' > ')
    password += p.recvline()[:-1]
for i  in range(8,12):
    p.sendline(f'{i}'.encode())
    p.recvuntil(b' > ')
    key += p.recvline()[:-1]
password_1 = b''
for i,j in zip(password,key):
    c = i ^ j
    if chr(c).isprintable():
        password_1 += c.to_bytes()

print(password_1)
print(len(password_1))

p.sendline(b'-1')
input()
p.sendlineafter(b'Enter the password > ',password_1)
p.interactive()

